(function() {var implementors = {};
implementors["bytes"] = [{"text":"impl AsMut&lt;[u8]&gt; for BytesMut","synthetic":false,"types":[]}];
implementors["crossbeam_epoch"] = [{"text":"impl&lt;T&gt; AsMut&lt;T&gt; for Owned&lt;T&gt;","synthetic":false,"types":[]}];
implementors["smallvec"] = [{"text":"impl&lt;A:&nbsp;Array&gt; AsMut&lt;[&lt;A as Array&gt;::Item]&gt; for SmallVec&lt;A&gt;","synthetic":false,"types":[]}];
implementors["tokio_io"] = [{"text":"impl&lt;T:&nbsp;AsMut&lt;[u8]&gt;&gt; AsMut&lt;[u8]&gt; for Window&lt;T&gt;","synthetic":false,"types":[]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()