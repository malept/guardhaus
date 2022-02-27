(function() {var implementors = {};
implementors["futures"] = [];
implementors["tokio_core"] = [{"text":"impl&lt;C:&nbsp;<a class=\"trait\" href=\"tokio_core/net/trait.UdpCodec.html\" title=\"trait tokio_core::net::UdpCodec\">UdpCodec</a>&gt; <a class=\"trait\" href=\"futures/sink/trait.Sink.html\" title=\"trait futures::sink::Sink\">Sink</a> for <a class=\"struct\" href=\"tokio_core/net/struct.UdpFramed.html\" title=\"struct tokio_core::net::UdpFramed\">UdpFramed</a>&lt;C&gt;","synthetic":false,"types":["tokio_core::net::udp::frame::UdpFramed"]}];
implementors["tokio_sync"] = [{"text":"impl&lt;T&gt; <a class=\"trait\" href=\"futures/sink/trait.Sink.html\" title=\"trait futures::sink::Sink\">Sink</a> for <a class=\"struct\" href=\"tokio_sync/mpsc/struct.Sender.html\" title=\"struct tokio_sync::mpsc::Sender\">Sender</a>&lt;T&gt;","synthetic":false,"types":["tokio_sync::mpsc::bounded::Sender"]},{"text":"impl&lt;T&gt; <a class=\"trait\" href=\"futures/sink/trait.Sink.html\" title=\"trait futures::sink::Sink\">Sink</a> for <a class=\"struct\" href=\"tokio_sync/mpsc/struct.UnboundedSender.html\" title=\"struct tokio_sync::mpsc::UnboundedSender\">UnboundedSender</a>&lt;T&gt;","synthetic":false,"types":["tokio_sync::mpsc::unbounded::UnboundedSender"]},{"text":"impl&lt;T&gt; <a class=\"trait\" href=\"futures/sink/trait.Sink.html\" title=\"trait futures::sink::Sink\">Sink</a> for <a class=\"struct\" href=\"tokio_sync/watch/struct.Sender.html\" title=\"struct tokio_sync::watch::Sender\">Sender</a>&lt;T&gt;","synthetic":false,"types":["tokio_sync::watch::Sender"]}];
implementors["tokio_udp"] = [{"text":"impl&lt;C:&nbsp;<a class=\"trait\" href=\"tokio_io/codec/encoder/trait.Encoder.html\" title=\"trait tokio_io::codec::encoder::Encoder\">Encoder</a>&gt; <a class=\"trait\" href=\"futures/sink/trait.Sink.html\" title=\"trait futures::sink::Sink\">Sink</a> for <a class=\"struct\" href=\"tokio_udp/struct.UdpFramed.html\" title=\"struct tokio_udp::UdpFramed\">UdpFramed</a>&lt;C&gt;","synthetic":false,"types":["tokio_udp::frame::UdpFramed"]}];
implementors["tokio_uds"] = [{"text":"impl&lt;A:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.59.0/core/convert/trait.AsRef.html\" title=\"trait core::convert::AsRef\">AsRef</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/1.59.0/std/path/struct.Path.html\" title=\"struct std::path::Path\">Path</a>&gt;, C:&nbsp;<a class=\"trait\" href=\"tokio_io/codec/encoder/trait.Encoder.html\" title=\"trait tokio_io::codec::encoder::Encoder\">Encoder</a>&gt; <a class=\"trait\" href=\"futures/sink/trait.Sink.html\" title=\"trait futures::sink::Sink\">Sink</a> for <a class=\"struct\" href=\"tokio_uds/struct.UnixDatagramFramed.html\" title=\"struct tokio_uds::UnixDatagramFramed\">UnixDatagramFramed</a>&lt;A, C&gt;","synthetic":false,"types":["tokio_uds::frame::UnixDatagramFramed"]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()