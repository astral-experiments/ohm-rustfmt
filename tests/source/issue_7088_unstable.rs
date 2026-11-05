// rustfmt-channels: nightly

#![crate_type = "lib"]
    cfg_select! {
        _ => {
            fn foo(){} {}
        }
}

cfg_select! { _ => {{} {}}}
