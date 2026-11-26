// rustfmt-use_try_shorthand: true

fn main() {
    let x = some_expr()?;

    let y = a
        .very
        .loooooooooooooooooooooooooooooooooooooong()
        .chain()
        .inside()
        .weeeeeeeeeeeeeee()?
        .test()
        .0
        .x;
}

fn test() {
    a?
}

fn issue1291() {
    fs::create_dir_all(&gitfiledir).chain_err(|| {
        format!(
            "failed to create the {} submodule directory for the workarea",
            name
        )
    })?;
}

fn nested_try_chain() {
    let x = outer().inner()?.0.next()?.value;
    let y = thing??.method()?.0;
}
