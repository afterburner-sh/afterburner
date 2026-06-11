// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `vm.SourceTextModule` + `vm.SyntheticModule` ES Module record
//! lifecycle. Each test pins one transition: parse → link → evaluate
//! → namespace, plus error / re-entry paths.

#![cfg(all(feature = "bin", feature = "ts"))]

use std::process::{Command, Stdio};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn run(src: &str) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-A")
        .arg("-e")
        .arg(src)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn")
}

fn assert_marker(out: &std::process::Output, marker: &str) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "burn failed.\nstdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.contains(marker),
        "missing marker `{marker}`. stdout={stdout}\nstderr={stderr}"
    );
}

// ---- SourceTextModule ----------------------------------------------

#[test]
fn source_text_module_initial_status_is_unlinked() {
    let out = run(r#"
        const vm = require('vm');
        const m = new vm.SourceTextModule('export const x = 1;');
        if (m.status === 'unlinked') console.log('UNLINKED-OK');
        else console.log('FAIL ' + m.status);
    "#);
    assert_marker(&out, "UNLINKED-OK");
}

#[test]
fn source_text_module_identifier_defaults_to_unique_string() {
    let out = run(r#"
        const vm = require('vm');
        const a = new vm.SourceTextModule('export const x = 1;');
        const b = new vm.SourceTextModule('export const y = 2;');
        if (typeof a.identifier === 'string' && a.identifier !== b.identifier)
            console.log('IDENT-OK');
    "#);
    assert_marker(&out, "IDENT-OK");
}

#[test]
fn source_text_module_identifier_accepts_user_value() {
    let out = run(r#"
        const vm = require('vm');
        const m = new vm.SourceTextModule('export {};', { identifier: 'foo.mjs' });
        if (m.identifier === 'foo.mjs') console.log('IDENT-USER-OK');
    "#);
    assert_marker(&out, "IDENT-USER-OK");
}

#[test]
fn source_text_module_extracts_dependency_specifiers() {
    let out = run(r#"
        const vm = require('vm');
        const m = new vm.SourceTextModule(`
            import { x } from 'foo';
            import 'bar';
            import * as ns from 'baz';
            export const y = 1;
        `);
        const ds = m.dependencySpecifiers.sort();
        if (ds.length === 3 && ds[0] === 'bar' && ds[1] === 'baz' && ds[2] === 'foo')
            console.log('DEPS-OK');
        else console.log('FAIL ' + JSON.stringify(ds));
    "#);
    assert_marker(&out, "DEPS-OK");
}

#[test]
fn source_text_module_link_then_evaluate_populates_namespace() {
    let out = run(r#"
        const vm = require('vm');
        async function main() {
            const m = new vm.SourceTextModule('export const x = 7;');
            await m.link(() => {});
            if (m.status !== 'linked') return console.log('FAIL link: ' + m.status);
            await m.evaluate();
            if (m.status === 'evaluated' && m.namespace.x === 7) console.log('LIFE-OK');
            else console.log('FAIL ' + m.status + ' x=' + m.namespace.x);
        }
        main().catch(e => console.log('CRASH ' + e.message));
    "#);
    assert_marker(&out, "LIFE-OK");
}

#[test]
fn source_text_module_default_export_lands_in_namespace() {
    let out = run(r#"
        const vm = require('vm');
        async function main() {
            const m = new vm.SourceTextModule('export default 42;');
            await m.link(() => {});
            await m.evaluate();
            if (m.namespace.default === 42) console.log('DEFAULT-OK');
        }
        main().catch(e => console.log('CRASH ' + e.message));
    "#);
    assert_marker(&out, "DEFAULT-OK");
}

#[test]
fn source_text_module_dependency_imports_are_wired_via_linker() {
    let out = run(r#"
        const vm = require('vm');
        async function main() {
            const dep = new vm.SourceTextModule('export const x = 5;');
            await dep.link(() => {});
            const main = new vm.SourceTextModule(
                "import { x } from 'dep'; export const doubled = x * 2;"
            );
            await main.link(async (spec) => {
                if (spec === 'dep') return dep;
                throw new Error('unknown ' + spec);
            });
            await main.evaluate();
            if (main.namespace.doubled === 10) console.log('LINKER-OK');
        }
        main().catch(e => console.log('CRASH ' + e.message));
    "#);
    assert_marker(&out, "LINKER-OK");
}

#[test]
fn source_text_module_linker_returning_namespace_object_directly_works() {
    let out = run(r#"
        const vm = require('vm');
        async function main() {
            // Accept a plain object as the linker result — Node tolerates
            // this if the dep is "already evaluated" (eg. a built-in).
            const main = new vm.SourceTextModule(
                "import { x } from 'shim'; export const y = x + 1;"
            );
            await main.link(async () => ({ x: 41 }));
            await main.evaluate();
            if (main.namespace.y === 42) console.log('SHIM-OK');
        }
        main().catch(e => console.log('CRASH ' + e.message));
    "#);
    assert_marker(&out, "SHIM-OK");
}

#[test]
fn source_text_module_evaluate_before_link_rejects() {
    let out = run(r#"
        const vm = require('vm');
        async function main() {
            const m = new vm.SourceTextModule('export const x = 1;');
            try {
                await m.evaluate();
                console.log('FAIL no-throw');
            } catch (e) {
                if (m.status === 'unlinked') console.log('PREMATURE-EVAL-OK');
            }
        }
        main().catch(e => console.log('CRASH ' + e.message));
    "#);
    assert_marker(&out, "PREMATURE-EVAL-OK");
}

#[test]
fn source_text_module_double_link_rejects() {
    let out = run(r#"
        const vm = require('vm');
        async function main() {
            const m = new vm.SourceTextModule('export const x = 1;');
            await m.link(() => {});
            try {
                await m.link(() => {});
                console.log('FAIL no-throw');
            } catch (_) {
                console.log('DOUBLE-LINK-OK');
            }
        }
        main().catch(e => console.log('CRASH ' + e.message));
    "#);
    assert_marker(&out, "DOUBLE-LINK-OK");
}

#[test]
fn source_text_module_evaluation_failure_sets_errored_status() {
    let out = run(r#"
        const vm = require('vm');
        async function main() {
            const m = new vm.SourceTextModule('throw new Error("boom"); export const x = 1;');
            await m.link(() => {});
            try {
                await m.evaluate();
                console.log('FAIL no-throw');
            } catch (e) {
                if (m.status === 'errored' && m.error.message === 'boom')
                    console.log('ERROR-STATE-OK');
                else console.log('FAIL status=' + m.status);
            }
        }
        main().catch(e => console.log('CRASH ' + e.message));
    "#);
    assert_marker(&out, "ERROR-STATE-OK");
}

#[test]
fn source_text_module_idempotent_re_evaluate_returns_undefined() {
    let out = run(r#"
        const vm = require('vm');
        async function main() {
            const m = new vm.SourceTextModule('export const x = 1;');
            await m.link(() => {});
            await m.evaluate();
            const r = await m.evaluate();
            if (r === undefined && m.status === 'evaluated') console.log('REEVAL-OK');
        }
        main().catch(e => console.log('CRASH ' + e.message));
    "#);
    assert_marker(&out, "REEVAL-OK");
}

#[test]
fn source_text_module_namespace_is_frozen_after_evaluate() {
    let out = run(r#"
        const vm = require('vm');
        async function main() {
            const m = new vm.SourceTextModule('export const x = 1;');
            await m.link(() => {});
            await m.evaluate();
            try {
                m.namespace.y = 2;
            } catch (_) {}
            if (m.namespace.y === undefined && Object.isFrozen(m.namespace))
                console.log('FROZEN-OK');
        }
        main().catch(e => console.log('CRASH ' + e.message));
    "#);
    assert_marker(&out, "FROZEN-OK");
}

#[test]
fn source_text_module_namespace_access_before_link_throws() {
    let out = run(r#"
        const vm = require('vm');
        const m = new vm.SourceTextModule('export const x = 1;');
        try {
            const _ = m.namespace;
            console.log('FAIL no-throw');
        } catch (_) {
            console.log('NAMESPACE-PREMATURE-OK');
        }
    "#);
    assert_marker(&out, "NAMESPACE-PREMATURE-OK");
}

// ---- SyntheticModule -----------------------------------------------

#[test]
fn synthetic_module_set_export_during_evaluate() {
    let out = run(r#"
        const vm = require('vm');
        async function main() {
            const m = new vm.SyntheticModule(['a', 'b'], function() {
                this.setExport('a', 1);
                this.setExport('b', 'two');
            });
            await m.link(() => {});
            await m.evaluate();
            if (m.namespace.a === 1 && m.namespace.b === 'two')
                console.log('SYN-OK');
        }
        main().catch(e => console.log('CRASH ' + e.message));
    "#);
    assert_marker(&out, "SYN-OK");
}

#[test]
fn synthetic_module_set_export_unknown_name_throws() {
    let out = run(r#"
        const vm = require('vm');
        async function main() {
            const m = new vm.SyntheticModule(['a'], function() {
                this.setExport('z', 99);
            });
            await m.link(() => {});
            try {
                await m.evaluate();
                console.log('FAIL no-throw');
            } catch (e) {
                if (e.message.indexOf('unknown export') >= 0
                    || e.message.indexOf('z') >= 0) console.log('SYN-UNKNOWN-OK');
            }
        }
        main().catch(e => console.log('CRASH ' + e.message));
    "#);
    assert_marker(&out, "SYN-UNKNOWN-OK");
}

#[test]
fn synthetic_module_status_progresses_through_lifecycle() {
    let out = run(r#"
        const vm = require('vm');
        async function main() {
            const m = new vm.SyntheticModule(['x'], function() {
                this.setExport('x', 7);
            });
            const states = [m.status];
            await m.link(() => {});
            states.push(m.status);
            await m.evaluate();
            states.push(m.status);
            if (states.join(',') === 'unlinked,linked,evaluated') console.log('SYN-LIFE-OK');
            else console.log('FAIL ' + states.join(','));
        }
        main().catch(e => console.log('CRASH ' + e.message));
    "#);
    assert_marker(&out, "SYN-LIFE-OK");
}

#[test]
fn synthetic_module_namespace_pre_populated_with_undefined_after_link() {
    let out = run(r#"
        const vm = require('vm');
        async function main() {
            const m = new vm.SyntheticModule(['a'], function() {});
            await m.link(() => {});
            // Before evaluate: name exists but value is undefined.
            if ('a' in m.namespace && m.namespace.a === undefined)
                console.log('SYN-PRE-OK');
        }
        main().catch(e => console.log('CRASH ' + e.message));
    "#);
    assert_marker(&out, "SYN-PRE-OK");
}

// ---- recursive linker ----------------------------------------------

#[test]
fn source_text_module_linker_recurses_through_unlinked_dep() {
    let out = run(r#"
        const vm = require('vm');
        async function main() {
            // dep is unlinked when handed to the parent's linker;
            // the parent's link() should recursively link it.
            const dep = new vm.SourceTextModule('export const v = 11;');
            const main = new vm.SourceTextModule(
                "import { v } from 'sub'; export const w = v + 1;"
            );
            await main.link(async (spec) => {
                if (spec === 'sub') return dep;
                throw new Error(spec);
            });
            if (dep.status !== 'linked') return console.log('FAIL dep status ' + dep.status);
            await main.evaluate();
            if (main.namespace.w === 12) console.log('REC-LINK-OK');
        }
        main().catch(e => console.log('CRASH ' + e.message));
    "#);
    assert_marker(&out, "REC-LINK-OK");
}

#[test]
fn source_text_module_two_imports_from_same_module_share_namespace() {
    let out = run(r#"
        const vm = require('vm');
        async function main() {
            const dep = new vm.SourceTextModule('export const a = 1; export const b = 2;');
            await dep.link(() => {});
            const main = new vm.SourceTextModule(
                "import { a, b } from 'shared'; export const sum = a + b;"
            );
            await main.link(async () => dep);
            await main.evaluate();
            if (main.namespace.sum === 3) console.log('SHARED-OK');
        }
        main().catch(e => console.log('CRASH ' + e.message));
    "#);
    assert_marker(&out, "SHARED-OK");
}

// ---- Module base ---------------------------------------------------

#[test]
fn module_base_class_is_exported() {
    let out = run(r#"
        const vm = require('vm');
        const m = new vm.SourceTextModule('export const x = 1;');
        if (m instanceof vm.Module) console.log('BASE-OK');
    "#);
    assert_marker(&out, "BASE-OK");
}

#[test]
fn synthetic_module_is_module_instance() {
    let out = run(r#"
        const vm = require('vm');
        const m = new vm.SyntheticModule([], function() {});
        if (m instanceof vm.Module) console.log('SYN-BASE-OK');
    "#);
    assert_marker(&out, "SYN-BASE-OK");
}
