// rustfmt-channels: stable,beta,dev

// Stable formatting preserves the tokens inside these invocations.
cfg_select! (
       unix     => 1,
       windows     => 1,
);

fn platform_value() -> u8 {
    cfg_select! {
        unix => {
            let value = 1;
            value
        },
        _ => 2,
    }
}
