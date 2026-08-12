//! Turning `(app, content_id, content_kind)` into something tvOS will open.
//!
//! The contract's content reference is deliberately not a URL: a Disney+ video id is the same
//! id on a Roku and on an Apple TV, and only the spelling of the request differs. This is the
//! spelling, and it is the one part of this driver that is *data about the world* rather than
//! protocol — so it is a table, kept together, easy to correct.
//!
//! # It rots, and that is expected
//!
//! Deep links are not an API anybody promised. Netflix's stopped working in September 2025 and
//! Paramount+'s stopped some time before that; both used to work. So the rule here is that a
//! service which is **not** in this table, or whose entry has been marked dead, still launches
//! — by bundle id, on its home screen — and the caller is told that is what happened. Reporting
//! success for a link that silently did nothing is the failure worth designing against.
//!
//! `_launchApp` takes either a bundle id or a URL, and picks by looking at the string, so both
//! kinds of answer below go the same way.

/// How one service spells "open this title".
struct Service {
    /// Matched loosely against what the device calls the app — people say "disney", the box
    /// says "Disney+", and the app list says whatever it says.
    aliases: &'static [&'static str],
    bundle: &'static str,
    /// `{id}` is replaced with the content id. `None` means: this app is installed and
    /// launchable, but nobody has a working deep link for it.
    template: Option<&'static str>,
    /// A series link that differs from the default, where the service has one.
    series: Option<&'static str>,
}

/// Confirmed working as of writing, from pyatv's documentation and the Home Assistant
/// community's own testing. Anything not listed still launches; it simply does not deep link.
const SERVICES: &[Service] = &[
    Service {
        aliases: &["appletv", "apple tv", "tv", "appletvplus", "apple tv+"],
        bundle: "com.apple.TVWatchList",
        template: Some("https://tv.apple.com/movie/{id}?action=play"),
        series: Some("https://tv.apple.com/show/{id}"),
    },
    Service {
        aliases: &["disney", "disney+", "disneyplus"],
        bundle: "com.disney.disneyplus",
        template: Some("https://www.disneyplus.com/video/{id}"),
        series: None,
    },
    Service {
        aliases: &["youtube"],
        bundle: "com.google.ios.youtube",
        template: Some("youtube://www.youtube.com/watch?v={id}"),
        series: None,
    },
    Service {
        aliases: &["hulu"],
        bundle: "com.hulu.plus",
        template: Some("hulu://watch/{id}"),
        series: Some("hulu://series/{id}"),
    },
    Service {
        aliases: &["pluto", "pluto tv"],
        bundle: "tv.pluto.ios",
        template: Some("https://pluto.tv/us/live-tv/{id}"),
        series: None,
    },
    Service {
        aliases: &["spotify"],
        bundle: "com.spotify.client",
        template: Some("spotify:?uri=spotify:album:{id}&play=true"),
        series: None,
    },
    // Both of these launch, and neither deep links any more. Listed *because* they do not:
    // without an entry there would be nothing to say why "play Wednesday on Netflix" opened a
    // home screen, and somebody would go looking for a bug in the driver.
    Service {
        aliases: &["netflix"],
        bundle: "com.netflix.Netflix",
        template: None,
        series: None,
    },
    Service {
        aliases: &["paramount", "paramount+", "paramountplus"],
        bundle: "com.cbsvideo.app",
        template: None,
        series: None,
    },
];

fn normalise(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect()
}

fn find(app: &str) -> Option<&'static Service> {
    let want = normalise(app);
    SERVICES.iter().find(|s| {
        s.aliases
            .iter()
            .any(|a| normalise(a) == want || want.starts_with(&normalise(a)))
    })
}

/// What to hand `_launchApp`, and whether the title made it in.
pub enum Launch {
    /// A URL that should open the title itself.
    DeepLink(String),
    /// Just the app. `why` explains it, and is meant to be said out loud.
    AppOnly { target: String, why: Option<String> },
}

/// Work out what to launch.
///
/// `app` is whatever the person or the assistant named; `installed` is what the device actually
/// reported, so a name that matched nothing in the table can still be launched if the box has
/// it. The two are separate on purpose — the table is about deep links, not about what exists.
pub fn resolve(
    app: &str,
    installed: Option<&str>,
    content_id: Option<&str>,
    content_kind: Option<&str>,
) -> Launch {
    let service = find(app);

    // The bundle id to fall back to: the one the device reported, if it reported one, otherwise
    // whatever the table knows. The device's own answer is better — it is the truth about this
    // box, where the table is a guess about the world.
    let target = installed
        .map(str::to_string)
        .or_else(|| service.map(|s| s.bundle.to_string()))
        .unwrap_or_else(|| app.to_string());

    let Some(id) = content_id.filter(|id| !id.is_empty()) else {
        return Launch::AppOnly {
            target,
            why: None,
        };
    };

    // Already a URL: somebody resolved it upstream, or it was copied out of a Share sheet. Send
    // it as-is rather than trying to take it apart.
    if id.contains("://") {
        return Launch::DeepLink(id.to_string());
    }

    let Some(service) = service else {
        return Launch::AppOnly {
            target,
            why: Some(format!(
                "opened {app}; this driver has no deep link for it, so it will be on its home \
                 screen"
            )),
        };
    };

    let is_series = matches!(content_kind, Some("series") | Some("season") | Some("episode"));
    let template = match (is_series, service.series, service.template) {
        (true, Some(series), _) => Some(series),
        (_, _, Some(default)) => Some(default),
        _ => None,
    };

    match template {
        Some(t) => Launch::DeepLink(t.replace("{id}", id)),
        None => Launch::AppOnly {
            target,
            why: Some(format!(
                "opened {app} on its home screen — it stopped honouring deep links, so it cannot \
                 be sent straight to a title"
            )),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(l: Launch) -> String {
        match l {
            Launch::DeepLink(u) => u,
            Launch::AppOnly { target, .. } => panic!("expected a deep link, got app {target}"),
        }
    }

    fn app_only(l: Launch) -> (String, Option<String>) {
        match l {
            Launch::AppOnly { target, why } => (target, why),
            Launch::DeepLink(u) => panic!("expected app only, got {u}"),
        }
    }

    #[test]
    fn people_do_not_say_the_full_service_name() {
        assert!(link(resolve("disney", None, Some("abc"), None)).contains("disneyplus.com"));
        assert!(link(resolve("Disney+", None, Some("abc"), None)).contains("disneyplus.com"));
        assert!(link(resolve("DisneyPlus", None, Some("abc"), None)).contains("disneyplus.com"));
    }

    /// A series and a film are different URLs on the services that distinguish them, and the
    /// contract's `content_kind` is the only thing that can say which.
    #[test]
    fn a_series_uses_the_series_template_where_there_is_one() {
        assert_eq!(
            link(resolve("hulu", None, Some("x1"), Some("series"))),
            "hulu://series/x1"
        );
        assert_eq!(
            link(resolve("hulu", None, Some("x1"), Some("movie"))),
            "hulu://watch/x1"
        );
        // An episode is a thing you watch, so it takes the series-shaped link on Hulu and the
        // show link on Apple TV. What matters is that it is not silently treated as a film.
        assert_eq!(
            link(resolve("hulu", None, Some("x1"), Some("episode"))),
            "hulu://series/x1"
        );
    }

    /// The whole reason `has_deep_link` exists. A dead service must launch *and say so*, not
    /// report success for a link that did nothing.
    #[test]
    fn a_service_that_stopped_deep_linking_launches_and_explains() {
        let (target, why) = app_only(resolve("Netflix", None, Some("80234304"), Some("series")));
        assert_eq!(target, "com.netflix.Netflix");
        let why = why.expect("a dead deep link has to be explained");
        assert!(why.contains("home screen"), "{why}");
    }

    /// An unknown service is still launchable — the device's own app list is the truth about
    /// what is installed, and the table is only about deep links.
    #[test]
    fn an_unknown_service_still_launches_by_what_the_device_reported() {
        let (target, why) = app_only(resolve(
            "Some Regional Broadcaster",
            Some("se.svt.play"),
            Some("abc"),
            None,
        ));
        assert_eq!(target, "se.svt.play");
        assert!(why.unwrap().contains("no deep link"));

        // And with no content id there is nothing to explain.
        let (target, why) = app_only(resolve("Whatever", Some("com.x.y"), None, None));
        assert_eq!(target, "com.x.y");
        assert!(why.is_none());
    }

    /// A URL that arrived already resolved goes straight through. Share sheets produce these and
    /// pulling them apart to rebuild them would only be a way to get them wrong.
    #[test]
    fn an_already_resolved_url_is_passed_through_untouched() {
        let url = "https://tv.apple.com/us/episode/foo/umc.cmc.abc123";
        assert_eq!(link(resolve("Apple TV", None, Some(url), Some("episode"))), url);
    }

    #[test]
    fn an_empty_content_id_is_the_same_as_none() {
        let (_, why) = app_only(resolve("Netflix", None, Some(""), None));
        assert!(why.is_none(), "an empty id is not a failed deep link");
    }
}
