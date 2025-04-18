(function() {
    var implementors = Object.fromEntries([["typenum",[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a> for <a class=\"struct\" href=\"typenum/array/struct.ATerm.html\" title=\"struct typenum::array::ATerm\">ATerm</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;<a class=\"struct\" href=\"typenum/bit/struct.B0.html\" title=\"struct typenum::bit::B0\">B0</a>&gt; for <a class=\"struct\" href=\"typenum/uint/struct.UTerm.html\" title=\"struct typenum::uint::UTerm\">UTerm</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;<a class=\"struct\" href=\"typenum/bit/struct.B1.html\" title=\"struct typenum::bit::B1\">B1</a>&gt; for <a class=\"struct\" href=\"typenum/uint/struct.UTerm.html\" title=\"struct typenum::uint::UTerm\">UTerm</a>"],["impl&lt;Al, Vl, Ar, Vr&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;<a class=\"struct\" href=\"typenum/array/struct.TArr.html\" title=\"struct typenum::array::TArr\">TArr</a>&lt;Vr, Ar&gt;&gt; for <a class=\"struct\" href=\"typenum/array/struct.TArr.html\" title=\"struct typenum::array::TArr\">TArr</a>&lt;Vl, Al&gt;<div class=\"where\">where\n    Al: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;Ar&gt;,\n    Vl: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;Vr&gt;,</div>"],["impl&lt;I: <a class=\"trait\" href=\"typenum/marker_traits/trait.Integer.html\" title=\"trait typenum::marker_traits::Integer\">Integer</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;I&gt; for <a class=\"struct\" href=\"typenum/int/struct.Z0.html\" title=\"struct typenum::int::Z0\">Z0</a>"],["impl&lt;U&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;<a class=\"struct\" href=\"typenum/bit/struct.B1.html\" title=\"struct typenum::bit::B1\">B1</a>&gt; for <a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;U, <a class=\"struct\" href=\"typenum/bit/struct.B1.html\" title=\"struct typenum::bit::B1\">B1</a>&gt;<div class=\"where\">where\n    U: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;<a class=\"struct\" href=\"typenum/bit/struct.B1.html\" title=\"struct typenum::bit::B1\">B1</a>&gt; + <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a>,\n    <a class=\"type\" href=\"typenum/operator_aliases/type.Add1.html\" title=\"type typenum::operator_aliases::Add1\">Add1</a>&lt;U&gt;: <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a>,</div>"],["impl&lt;U: <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;<a class=\"struct\" href=\"typenum/int/struct.Z0.html\" title=\"struct typenum::int::Z0\">Z0</a>&gt; for <a class=\"struct\" href=\"typenum/int/struct.NInt.html\" title=\"struct typenum::int::NInt\">NInt</a>&lt;U&gt;"],["impl&lt;U: <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;<a class=\"struct\" href=\"typenum/int/struct.Z0.html\" title=\"struct typenum::int::Z0\">Z0</a>&gt; for <a class=\"struct\" href=\"typenum/int/struct.PInt.html\" title=\"struct typenum::int::PInt\">PInt</a>&lt;U&gt;"],["impl&lt;U: <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;<a class=\"struct\" href=\"typenum/bit/struct.B1.html\" title=\"struct typenum::bit::B1\">B1</a>&gt; for <a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;U, <a class=\"struct\" href=\"typenum/bit/struct.B0.html\" title=\"struct typenum::bit::B0\">B0</a>&gt;"],["impl&lt;U: <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;U&gt; for <a class=\"struct\" href=\"typenum/uint/struct.UTerm.html\" title=\"struct typenum::uint::UTerm\">UTerm</a>"],["impl&lt;U: <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a>, B: <a class=\"trait\" href=\"typenum/marker_traits/trait.Bit.html\" title=\"trait typenum::marker_traits::Bit\">Bit</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;<a class=\"struct\" href=\"typenum/bit/struct.B0.html\" title=\"struct typenum::bit::B0\">B0</a>&gt; for <a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;U, B&gt;"],["impl&lt;U: <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a>, B: <a class=\"trait\" href=\"typenum/marker_traits/trait.Bit.html\" title=\"trait typenum::marker_traits::Bit\">Bit</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;<a class=\"struct\" href=\"typenum/uint/struct.UTerm.html\" title=\"struct typenum::uint::UTerm\">UTerm</a>&gt; for <a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;U, B&gt;"],["impl&lt;Ul, Ur: <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;<a class=\"struct\" href=\"typenum/int/struct.NInt.html\" title=\"struct typenum::int::NInt\">NInt</a>&lt;Ur&gt;&gt; for <a class=\"struct\" href=\"typenum/int/struct.NInt.html\" title=\"struct typenum::int::NInt\">NInt</a>&lt;Ul&gt;<div class=\"where\">where\n    Ul: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;Ur&gt; + <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>,\n    &lt;Ul as <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;Ur&gt;&gt;::<a class=\"associatedtype\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html#associatedtype.Output\" title=\"type core::ops::arith::Add::Output\">Output</a>: <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>,</div>"],["impl&lt;Ul, Ur: <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;<a class=\"struct\" href=\"typenum/int/struct.NInt.html\" title=\"struct typenum::int::NInt\">NInt</a>&lt;Ur&gt;&gt; for <a class=\"struct\" href=\"typenum/int/struct.PInt.html\" title=\"struct typenum::int::PInt\">PInt</a>&lt;Ul&gt;<div class=\"where\">where\n    Ul: <a class=\"trait\" href=\"typenum/type_operators/trait.Cmp.html\" title=\"trait typenum::type_operators::Cmp\">Cmp</a>&lt;Ur&gt; + PrivateIntegerAdd&lt;&lt;Ul as <a class=\"trait\" href=\"typenum/type_operators/trait.Cmp.html\" title=\"trait typenum::type_operators::Cmp\">Cmp</a>&lt;Ur&gt;&gt;::<a class=\"associatedtype\" href=\"typenum/type_operators/trait.Cmp.html#associatedtype.Output\" title=\"type typenum::type_operators::Cmp::Output\">Output</a>, Ur&gt; + <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>,</div>"],["impl&lt;Ul, Ur: <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;<a class=\"struct\" href=\"typenum/int/struct.PInt.html\" title=\"struct typenum::int::PInt\">PInt</a>&lt;Ur&gt;&gt; for <a class=\"struct\" href=\"typenum/int/struct.PInt.html\" title=\"struct typenum::int::PInt\">PInt</a>&lt;Ul&gt;<div class=\"where\">where\n    Ul: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;Ur&gt; + <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>,\n    &lt;Ul as <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;Ur&gt;&gt;::<a class=\"associatedtype\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html#associatedtype.Output\" title=\"type core::ops::arith::Add::Output\">Output</a>: <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>,</div>"],["impl&lt;Ul, Ur: <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;<a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;Ur, <a class=\"struct\" href=\"typenum/bit/struct.B0.html\" title=\"struct typenum::bit::B0\">B0</a>&gt;&gt; for <a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;Ul, <a class=\"struct\" href=\"typenum/bit/struct.B0.html\" title=\"struct typenum::bit::B0\">B0</a>&gt;<div class=\"where\">where\n    Ul: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;Ur&gt; + <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a>,</div>"],["impl&lt;Ul, Ur: <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;<a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;Ur, <a class=\"struct\" href=\"typenum/bit/struct.B0.html\" title=\"struct typenum::bit::B0\">B0</a>&gt;&gt; for <a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;Ul, <a class=\"struct\" href=\"typenum/bit/struct.B1.html\" title=\"struct typenum::bit::B1\">B1</a>&gt;<div class=\"where\">where\n    Ul: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;Ur&gt; + <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a>,</div>"],["impl&lt;Ul, Ur: <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;<a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;Ur, <a class=\"struct\" href=\"typenum/bit/struct.B1.html\" title=\"struct typenum::bit::B1\">B1</a>&gt;&gt; for <a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;Ul, <a class=\"struct\" href=\"typenum/bit/struct.B0.html\" title=\"struct typenum::bit::B0\">B0</a>&gt;<div class=\"where\">where\n    Ul: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;Ur&gt; + <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a>,</div>"],["impl&lt;Ul, Ur: <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;<a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;Ur, <a class=\"struct\" href=\"typenum/bit/struct.B1.html\" title=\"struct typenum::bit::B1\">B1</a>&gt;&gt; for <a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;Ul, <a class=\"struct\" href=\"typenum/bit/struct.B1.html\" title=\"struct typenum::bit::B1\">B1</a>&gt;<div class=\"where\">where\n    Ul: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;Ur&gt; + <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a>,\n    <a class=\"type\" href=\"typenum/operator_aliases/type.Sum.html\" title=\"type typenum::operator_aliases::Sum\">Sum</a>&lt;Ul, Ur&gt;: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;<a class=\"struct\" href=\"typenum/bit/struct.B1.html\" title=\"struct typenum::bit::B1\">B1</a>&gt;,</div>"],["impl&lt;Ul: <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>, Ur&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;<a class=\"struct\" href=\"typenum/int/struct.PInt.html\" title=\"struct typenum::int::PInt\">PInt</a>&lt;Ur&gt;&gt; for <a class=\"struct\" href=\"typenum/int/struct.NInt.html\" title=\"struct typenum::int::NInt\">NInt</a>&lt;Ul&gt;<div class=\"where\">where\n    Ur: <a class=\"trait\" href=\"typenum/type_operators/trait.Cmp.html\" title=\"trait typenum::type_operators::Cmp\">Cmp</a>&lt;Ul&gt; + PrivateIntegerAdd&lt;&lt;Ur as <a class=\"trait\" href=\"typenum/type_operators/trait.Cmp.html\" title=\"trait typenum::type_operators::Cmp\">Cmp</a>&lt;Ul&gt;&gt;::<a class=\"associatedtype\" href=\"typenum/type_operators/trait.Cmp.html#associatedtype.Output\" title=\"type typenum::type_operators::Cmp::Output\">Output</a>, Ul&gt; + <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>,</div>"]]]]);
    if (window.register_implementors) {
        window.register_implementors(implementors);
    } else {
        window.pending_implementors = implementors;
    }
})()
//{"start":57,"fragment_lengths":[17803]}