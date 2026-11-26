// rustfmt-max_width: 44

fn lists() {
    log(value);
    log(
        // leading
        value, // trailing
    );
    run(|| {
        visit(alpha, beta, gamma);
        visit(delta, epsilon);
    });
    collect(
        first::entry, // ordinary
        café::entrée, // Unicode
        other_module::longer_name, // aligned
    );
}
