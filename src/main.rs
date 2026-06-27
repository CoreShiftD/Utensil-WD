// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/

mod proc_scan {
    use coreshift_core::uid::proc_uid;

    pub fn scan_user_pids() -> Vec<(i32, u32)> {
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir("/proc") {
            for e in rd.flatten() {
                if let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() {
                    if let Ok(uid) = proc_uid(pid) {
                        if uid >= 10000 {
                            out.push((pid, uid));
                        }
                    }
                }
            }
        }
        out
    }
}

mod punish {
    use coreshift_core::spawn::{SpawnOptions, SpawnBackend};
    use coreshift_core::{log_info, log_warn};
    use std::collections::HashMap;

    const TAG: &str = "utensil-wd";

    // 0=none  1=killed  2=frozen  3=sticky-frozen
    pub struct PunishMap(pub HashMap<String, u8>);

    impl PunishMap {
        pub fn new() -> Self { Self(HashMap::new()) }

        pub fn level(&self, pkg: &str) -> u8 { *self.0.get(pkg).unwrap_or(&0) }

        pub fn escalate(&mut self, pkg: &str) {
            let cur = self.level(pkg);
            if cur >= 3 { return; } // already at sticky-freeze, no re-issue
            let next = cur + 1;
            self.0.insert(pkg.to_string(), next);
            match next {
                1 => { log_info!(TAG, "kill {pkg}");
                       act(&["kill", pkg]); }
                2 => { log_info!(TAG, "freeze {pkg}");
                       act(&["freeze", pkg]); }
                _ => { log_info!(TAG, "freeze --sticky {pkg}");
                       act(&["freeze", "--sticky", pkg]); }
            }
        }

        pub fn reverse(&mut self, pkg: &str) {
            if let Some(lvl) = self.0.remove(pkg) {
                if lvl >= 2 {
                    log_info!(TAG, "unfreeze {pkg}");
                    act(&["unfreeze", pkg]);
                } else if lvl == 1 {
                    log_info!(TAG, "cleared kill-state {pkg} (foreground)");
                }
            }
        }
    }

    fn act(args: &[&str]) {
        let mut argv = vec!["/system/bin/cmd".to_string(), "activity".to_string()];
        argv.extend(args.iter().map(|s| s.to_string()));
        match SpawnOptions::builder(argv, SpawnBackend::PosixSpawn)
            .timeout_ms(5000)
            .build()
            .and_then(|o| o.run())
        {
            Err(e) => log_warn!(TAG, "cmd activity: {e}"),
            Ok(_)  => {}
        }
    }
}

use coreshift_core::android_property::android_property_set;
use coreshift_core::reactor::{Event, Fd, Reactor};
use coreshift_core::{log_error, log_info};
use coreshift_foreground::blocklist::Blocklist;
use coreshift_foreground::cache::UidCache;
use coreshift_foreground::resolver::Resolver;
use coreshift_foreground::terminal_apps::TerminalApps;
use punish::PunishMap;
use std::collections::HashSet;
use std::time::Duration;

const TAG:       &str = "utensil-wd";
const TICK_PROP: &str = "debug.tracing.watchdog_tick";
const UTENSIL:   &str = "/data/local/tmp/Utensil/";
const WL_CONF:   &str = "/data/local/tmp/Utensil/watchdog_whitelist.conf";
const TA_CONF:   &str = "/data/local/tmp/Utensil/terminal_apps.conf";
const PKG_XML:   &str = "/data/system/packages.xml";
const INTERVAL:  Duration = Duration::from_secs(15 * 60);

fn drain_timer(fd: &Fd) {
    let mut buf = [0u8; 8];
    while let Ok(Some(_)) = fd.read_slice(&mut buf) {}
}

fn main() {
    log_info!(TAG, "start pid={}", std::process::id());

    let _ = std::fs::create_dir_all(UTENSIL);

    let mut cache = UidCache::new(UTENSIL);
    cache.load_or_refresh(PKG_XML);

    let launcher  = Blocklist::resolve_launcher();
    let defaults  = Blocklist::resolve_defaults();
    let blocklist = Blocklist::load_or_create(WL_CONF, defaults, false);
    let terminal  = TerminalApps::load_or_create(TA_CONF);

    let mut resolver = Resolver::new(cache, blocklist, terminal, launcher.clone());
    let mut punish   = PunishMap::new();
    let mut tick: u64 = 0;

    let mut reactor = Reactor::new().unwrap_or_else(|e| {
        log_error!(TAG, "reactor: {e}"); std::process::exit(1);
    });
    let timer = Fd::timerfd().unwrap_or_else(|e| {
        log_error!(TAG, "timerfd: {e}"); std::process::exit(1);
    });
    let timer_tok = reactor.add(&timer, true, false).expect("add timer");

    timer.set_timer_oneshot(Some(INTERVAL)).unwrap_or_else(|e| {
        log_error!(TAG, "arm: {e}"); std::process::exit(1);
    });

    let mut events: Vec<Event> = Vec::new();

    loop {
        events.clear();
        match reactor.wait(&mut events, 4, -1) {
            Err(_) | Ok(0) => continue,
            Ok(_) => {}
        }

        if events.iter().all(|ev| ev.token != timer_tok) {
            continue;
        }

        drain_timer(&timer);
        let _ = timer.set_timer_oneshot(Some(INTERVAL));
        tick += 1;
        let _ = android_property_set(TICK_PROP, &tick.to_string());
        log_info!(TAG, "tick={tick}");

        // Resolve current foreground app (also refreshes cgroup state internally).
        let fg_pkg = resolver.resolve().map(|(pkg, _, _)| pkg);
        log_info!(TAG, "foreground={:?}", fg_pkg);

        // Reverse punishment for anything now in foreground.
        if let Some(ref fg) = fg_pkg {
            punish.reverse(fg);
        }

        // Scan all user pids → background pkg set.
        let mut live_bg: HashSet<String> = HashSet::new();
        for (_, uid) in proc_scan::scan_user_pids() {
            if let Some(pkg) = resolver.cache.get_package(uid) {
                if resolver.blocklist.is_blocked(&pkg) { continue; }
                if launcher.as_deref() == Some(pkg.as_str()) { continue; }
                if fg_pkg.as_deref() == Some(pkg.as_str()) { continue; }
                live_bg.insert(pkg);
            }
        }

        // Escalate punishments for surviving background apps.
        for pkg in &live_bg {
            punish.escalate(pkg);
        }

        // State persists across process death — punishment escalates when app restarts.
    }
}
