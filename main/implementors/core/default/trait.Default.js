(function() {var implementors = {};
implementors["byteorder"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"enum\" href=\"byteorder/enum.BigEndian.html\" title=\"enum byteorder::BigEndian\">BigEndian</a>","synthetic":false,"types":["byteorder::BigEndian"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"enum\" href=\"byteorder/enum.LittleEndian.html\" title=\"enum byteorder::LittleEndian\">LittleEndian</a>","synthetic":false,"types":["byteorder::LittleEndian"]}];
implementors["bytes"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"bytes/struct.Bytes.html\" title=\"struct bytes::Bytes\">Bytes</a>","synthetic":false,"types":["bytes::bytes::Bytes"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"bytes/struct.BytesMut.html\" title=\"struct bytes::BytesMut\">BytesMut</a>","synthetic":false,"types":["bytes::bytes::BytesMut"]}];
implementors["crossbeam_epoch"] = [{"text":"impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"crossbeam_epoch/struct.Atomic.html\" title=\"struct crossbeam_epoch::Atomic\">Atomic</a>&lt;T&gt;","synthetic":false,"types":["crossbeam_epoch::atomic::Atomic"]},{"text":"impl&lt;'g, T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"crossbeam_epoch/struct.Shared.html\" title=\"struct crossbeam_epoch::Shared\">Shared</a>&lt;'g, T&gt;","synthetic":false,"types":["crossbeam_epoch::atomic::Shared"]}];
implementors["crossbeam_queue"] = [{"text":"impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"crossbeam_queue/struct.SegQueue.html\" title=\"struct crossbeam_queue::SegQueue\">SegQueue</a>&lt;T&gt;","synthetic":false,"types":["crossbeam_queue::seg_queue::SegQueue"]}];
implementors["crossbeam_utils"] = [{"text":"impl&lt;T:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"crossbeam_utils/atomic/struct.AtomicCell.html\" title=\"struct crossbeam_utils::atomic::AtomicCell\">AtomicCell</a>&lt;T&gt;","synthetic":false,"types":["crossbeam_utils::atomic::atomic_cell::AtomicCell"]},{"text":"impl&lt;T:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"crossbeam_utils/struct.CachePadded.html\" title=\"struct crossbeam_utils::CachePadded\">CachePadded</a>&lt;T&gt;","synthetic":false,"types":["crossbeam_utils::cache_padded::CachePadded"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"crossbeam_utils/struct.Backoff.html\" title=\"struct crossbeam_utils::Backoff\">Backoff</a>","synthetic":false,"types":["crossbeam_utils::backoff::Backoff"]},{"text":"impl&lt;T:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"crossbeam_utils/sync/struct.ShardedLock.html\" title=\"struct crossbeam_utils::sync::ShardedLock\">ShardedLock</a>&lt;T&gt;","synthetic":false,"types":["crossbeam_utils::sync::sharded_lock::ShardedLock"]}];
implementors["fnv"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"fnv/struct.FnvHasher.html\" title=\"struct fnv::FnvHasher\">FnvHasher</a>","synthetic":false,"types":["fnv::FnvHasher"]}];
implementors["futures"] = [{"text":"impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"futures/stream/futures_unordered/struct.FuturesUnordered.html\" title=\"struct futures::stream::futures_unordered::FuturesUnordered\">FuturesUnordered</a>&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: <a class=\"trait\" href=\"futures/future/trait.Future.html\" title=\"trait futures::future::Future\">Future</a>,&nbsp;</span>","synthetic":false,"types":["futures::stream::futures_unordered::FuturesUnordered"]},{"text":"impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"futures/stream/struct.FuturesOrdered.html\" title=\"struct futures::stream::FuturesOrdered\">FuturesOrdered</a>&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: <a class=\"trait\" href=\"futures/future/trait.Future.html\" title=\"trait futures::future::Future\">Future</a>,&nbsp;</span>","synthetic":false,"types":["futures::stream::futures_ordered::FuturesOrdered"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"futures/task/struct.AtomicTask.html\" title=\"struct futures::task::AtomicTask\">AtomicTask</a>","synthetic":false,"types":["futures::task_impl::atomic_task::AtomicTask"]}];
implementors["hyper"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"hyper/client/struct.Config.html\" title=\"struct hyper::client::Config\">Config</a>&lt;<a class=\"struct\" href=\"hyper/client/struct.UseDefaultConnector.html\" title=\"struct hyper::client::UseDefaultConnector\">UseDefaultConnector</a>, <a class=\"struct\" href=\"hyper/struct.Body.html\" title=\"struct hyper::Body\">Body</a>&gt;","synthetic":false,"types":["hyper::client::Config"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"enum\" href=\"hyper/enum.Method.html\" title=\"enum hyper::Method\">Method</a>","synthetic":false,"types":["hyper::method::Method"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"hyper/header/struct.Quality.html\" title=\"struct hyper::header::Quality\">Quality</a>","synthetic":false,"types":["hyper::header::shared::quality_item::Quality"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"hyper/header/struct.Headers.html\" title=\"struct hyper::header::Headers\">Headers</a>","synthetic":false,"types":["hyper::header::Headers"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"hyper/struct.Body.html\" title=\"struct hyper::Body\">Body</a>","synthetic":false,"types":["hyper::proto::body::Body"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"hyper/struct.Chunk.html\" title=\"struct hyper::Chunk\">Chunk</a>","synthetic":false,"types":["hyper::proto::chunk::Chunk"]},{"text":"impl&lt;B&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"hyper/struct.Response.html\" title=\"struct hyper::Response\">Response</a>&lt;B&gt;","synthetic":false,"types":["hyper::proto::response::Response"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"enum\" href=\"hyper/enum.StatusCode.html\" title=\"enum hyper::StatusCode\">StatusCode</a>","synthetic":false,"types":["hyper::status::StatusCode"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"hyper/struct.Uri.html\" title=\"struct hyper::Uri\">Uri</a>","synthetic":false,"types":["hyper::uri::Uri"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"enum\" href=\"hyper/enum.HttpVersion.html\" title=\"enum hyper::HttpVersion\">HttpVersion</a>","synthetic":false,"types":["hyper::version::HttpVersion"]}];
implementors["language_tags"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"language_tags/struct.LanguageTag.html\" title=\"struct language_tags::LanguageTag\">LanguageTag</a>","synthetic":false,"types":["language_tags::LanguageTag"]}];
implementors["lock_api"] = [{"text":"impl&lt;R:&nbsp;<a class=\"trait\" href=\"lock_api/trait.RawMutex.html\" title=\"trait lock_api::RawMutex\">RawMutex</a>, T:&nbsp;?<a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"lock_api/struct.Mutex.html\" title=\"struct lock_api::Mutex\">Mutex</a>&lt;R, T&gt;","synthetic":false,"types":["lock_api::mutex::Mutex"]},{"text":"impl&lt;R:&nbsp;<a class=\"trait\" href=\"lock_api/trait.RawMutex.html\" title=\"trait lock_api::RawMutex\">RawMutex</a>, G:&nbsp;<a class=\"trait\" href=\"lock_api/trait.GetThreadId.html\" title=\"trait lock_api::GetThreadId\">GetThreadId</a>, T:&nbsp;?<a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"lock_api/struct.ReentrantMutex.html\" title=\"struct lock_api::ReentrantMutex\">ReentrantMutex</a>&lt;R, G, T&gt;","synthetic":false,"types":["lock_api::remutex::ReentrantMutex"]},{"text":"impl&lt;R:&nbsp;<a class=\"trait\" href=\"lock_api/trait.RawRwLock.html\" title=\"trait lock_api::RawRwLock\">RawRwLock</a>, T:&nbsp;?<a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"lock_api/struct.RwLock.html\" title=\"struct lock_api::RwLock\">RwLock</a>&lt;R, T&gt;","synthetic":false,"types":["lock_api::rwlock::RwLock"]}];
implementors["openssl"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"openssl/sha/struct.Sha1.html\" title=\"struct openssl::sha::Sha1\">Sha1</a>","synthetic":false,"types":["openssl::sha::Sha1"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"openssl/sha/struct.Sha224.html\" title=\"struct openssl::sha::Sha224\">Sha224</a>","synthetic":false,"types":["openssl::sha::Sha224"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"openssl/sha/struct.Sha256.html\" title=\"struct openssl::sha::Sha256\">Sha256</a>","synthetic":false,"types":["openssl::sha::Sha256"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"openssl/sha/struct.Sha384.html\" title=\"struct openssl::sha::Sha384\">Sha384</a>","synthetic":false,"types":["openssl::sha::Sha384"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"openssl/sha/struct.Sha512.html\" title=\"struct openssl::sha::Sha512\">Sha512</a>","synthetic":false,"types":["openssl::sha::Sha512"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"openssl/x509/extension/struct.BasicConstraints.html\" title=\"struct openssl::x509::extension::BasicConstraints\">BasicConstraints</a>","synthetic":false,"types":["openssl::x509::extension::BasicConstraints"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"openssl/x509/extension/struct.KeyUsage.html\" title=\"struct openssl::x509::extension::KeyUsage\">KeyUsage</a>","synthetic":false,"types":["openssl::x509::extension::KeyUsage"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"openssl/x509/extension/struct.ExtendedKeyUsage.html\" title=\"struct openssl::x509::extension::ExtendedKeyUsage\">ExtendedKeyUsage</a>","synthetic":false,"types":["openssl::x509::extension::ExtendedKeyUsage"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"openssl/x509/extension/struct.SubjectKeyIdentifier.html\" title=\"struct openssl::x509::extension::SubjectKeyIdentifier\">SubjectKeyIdentifier</a>","synthetic":false,"types":["openssl::x509::extension::SubjectKeyIdentifier"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"openssl/x509/extension/struct.AuthorityKeyIdentifier.html\" title=\"struct openssl::x509::extension::AuthorityKeyIdentifier\">AuthorityKeyIdentifier</a>","synthetic":false,"types":["openssl::x509::extension::AuthorityKeyIdentifier"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"openssl/x509/extension/struct.SubjectAlternativeName.html\" title=\"struct openssl::x509::extension::SubjectAlternativeName\">SubjectAlternativeName</a>","synthetic":false,"types":["openssl::x509::extension::SubjectAlternativeName"]}];
implementors["parking_lot"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"parking_lot/struct.Condvar.html\" title=\"struct parking_lot::Condvar\">Condvar</a>","synthetic":false,"types":["parking_lot::condvar::Condvar"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"parking_lot/struct.Once.html\" title=\"struct parking_lot::Once\">Once</a>","synthetic":false,"types":["parking_lot::once::Once"]}];
implementors["parking_lot_core"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"parking_lot_core/struct.UnparkResult.html\" title=\"struct parking_lot_core::UnparkResult\">UnparkResult</a>","synthetic":false,"types":["parking_lot_core::parking_lot::UnparkResult"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"parking_lot_core/struct.SpinWait.html\" title=\"struct parking_lot_core::SpinWait\">SpinWait</a>","synthetic":false,"types":["parking_lot_core::spinwait::SpinWait"]}];
implementors["rand"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"rand/reseeding/struct.ReseedWithDefault.html\" title=\"struct rand::reseeding::ReseedWithDefault\">ReseedWithDefault</a>","synthetic":false,"types":["rand::reseeding::ReseedWithDefault"]}];
implementors["slab"] = [{"text":"impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"slab/struct.Slab.html\" title=\"struct slab::Slab\">Slab</a>&lt;T&gt;","synthetic":false,"types":["slab::Slab"]}];
implementors["smallvec"] = [{"text":"impl&lt;A:&nbsp;<a class=\"trait\" href=\"smallvec/trait.Array.html\" title=\"trait smallvec::Array\">Array</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"smallvec/struct.SmallVec.html\" title=\"struct smallvec::SmallVec\">SmallVec</a>&lt;A&gt;","synthetic":false,"types":["smallvec::SmallVec"]}];
implementors["tokio_reactor"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"tokio_reactor/struct.Handle.html\" title=\"struct tokio_reactor::Handle\">Handle</a>","synthetic":false,"types":["tokio_reactor::Handle"]}];
implementors["tokio_sync"] = [{"text":"impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"tokio_sync/lock/struct.Lock.html\" title=\"struct tokio_sync::lock::Lock\">Lock</a>&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>,&nbsp;</span>","synthetic":false,"types":["tokio_sync::lock::Lock"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"tokio_sync/task/struct.AtomicTask.html\" title=\"struct tokio_sync::task::AtomicTask\">AtomicTask</a>","synthetic":false,"types":["tokio_sync::task::atomic_task::AtomicTask"]}];
implementors["tokio_timer"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"tokio_timer/clock/struct.Clock.html\" title=\"struct tokio_timer::clock::Clock\">Clock</a>","synthetic":false,"types":["tokio_timer::clock::clock::Clock"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"tokio_timer/timer/struct.Handle.html\" title=\"struct tokio_timer::timer::Handle\">Handle</a>","synthetic":false,"types":["tokio_timer::timer::handle::Handle"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"tokio_timer/timer/struct.Timer.html\" title=\"struct tokio_timer::timer::Timer\">Timer</a>&lt;<a class=\"struct\" href=\"tokio_executor/park/struct.ParkThread.html\" title=\"struct tokio_executor::park::ParkThread\">ParkThread</a>, <a class=\"struct\" href=\"tokio_timer/clock/struct.Clock.html\" title=\"struct tokio_timer::clock::Clock\">SystemNow</a>&gt;","synthetic":false,"types":["tokio_timer::timer::Timer"]}];
implementors["unicase"] = [{"text":"impl&lt;S:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"unicase/struct.Ascii.html\" title=\"struct unicase::Ascii\">Ascii</a>&lt;S&gt;","synthetic":false,"types":["unicase::Ascii"]},{"text":"impl&lt;S:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.AsRef.html\" title=\"trait core::convert::AsRef\">AsRef</a>&lt;str&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"unicase/struct.UniCase.html\" title=\"struct unicase::UniCase\">UniCase</a>&lt;S&gt;","synthetic":false,"types":["unicase::UniCase"]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()