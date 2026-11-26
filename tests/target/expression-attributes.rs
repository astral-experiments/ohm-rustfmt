fn example() {
    example::f(
        #[cfg(test)] /* keep */ a::b::<C>(),
        <Thing as Trait>::r#type /* keep */ (),
        [/* inner */ Foo::new()],
    );
    // comment with an attribute-free expression
    let x = do_it!("hello", 20);
}
