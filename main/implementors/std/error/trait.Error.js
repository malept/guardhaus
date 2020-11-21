(function() {var implementors = {};
implementors["base64"] = [{"text":"impl Error for DecodeError","synthetic":false,"types":[]}];
implementors["futures"] = [{"text":"impl&lt;E&gt; Error for SharedError&lt;E&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;E: Error,&nbsp;</span>","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;Any&gt; Error for ReuniteError&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl Error for Canceled","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;Any&gt; Error for SendError&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;Any&gt; Error for TrySendError&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;Any&gt; Error for SendError&lt;T&gt;","synthetic":false,"types":[]}];
implementors["hex"] = [{"text":"impl Error for FromHexError","synthetic":false,"types":[]}];
implementors["httparse"] = [{"text":"impl Error for Error","synthetic":false,"types":[]}];
implementors["hyper"] = [{"text":"impl Error for Error","synthetic":false,"types":[]},{"text":"impl Error for UriError","synthetic":false,"types":[]}];
implementors["language_tags"] = [{"text":"impl Error for Error","synthetic":false,"types":[]}];
implementors["log"] = [{"text":"impl Error for SetLoggerError","synthetic":false,"types":[]},{"text":"impl Error for ShutdownLoggerError","synthetic":false,"types":[]}];
implementors["mime"] = [{"text":"impl Error for FromStrError","synthetic":false,"types":[]}];
implementors["openssl"] = [{"text":"impl Error for ErrorStack","synthetic":false,"types":[]},{"text":"impl Error for Error","synthetic":false,"types":[]},{"text":"impl Error for Error","synthetic":false,"types":[]},{"text":"impl&lt;S:&nbsp;Debug&gt; Error for HandshakeError&lt;S&gt;","synthetic":false,"types":[]},{"text":"impl Error for X509VerifyResult","synthetic":false,"types":[]}];
implementors["rand"] = [{"text":"impl Error for TimerError","synthetic":false,"types":[]}];
implementors["time"] = [{"text":"impl Error for OutOfRangeError","synthetic":false,"types":[]},{"text":"impl Error for ParseError","synthetic":false,"types":[]}];
implementors["tokio"] = [{"text":"impl Error for FrameTooBig","synthetic":false,"types":[]}];
implementors["tokio_current_thread"] = [{"text":"impl Error for RunError","synthetic":false,"types":[]},{"text":"impl Error for RunTimeoutError","synthetic":false,"types":[]},{"text":"impl Error for TurnError","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;Debug&gt; Error for BlockError&lt;T&gt;","synthetic":false,"types":[]}];
implementors["tokio_executor"] = [{"text":"impl Error for EnterError","synthetic":false,"types":[]},{"text":"impl Error for SpawnError","synthetic":false,"types":[]}];
implementors["tokio_reactor"] = [{"text":"impl Error for SetFallbackError","synthetic":false,"types":[]}];
implementors["tokio_sync"] = [{"text":"impl Error for SendError","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;Debug&gt; Error for TrySendError&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl Error for RecvError","synthetic":false,"types":[]},{"text":"impl Error for UnboundedSendError","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;Debug&gt; Error for UnboundedTrySendError&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl Error for UnboundedRecvError","synthetic":false,"types":[]},{"text":"impl Error for RecvError","synthetic":false,"types":[]},{"text":"impl Error for TryRecvError","synthetic":false,"types":[]},{"text":"impl Error for AcquireError","synthetic":false,"types":[]},{"text":"impl Error for TryAcquireError","synthetic":false,"types":[]},{"text":"impl Error for RecvError","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;Debug&gt; Error for SendError&lt;T&gt;","synthetic":false,"types":[]}];
implementors["tokio_threadpool"] = [{"text":"impl Error for BlockingError","synthetic":false,"types":[]},{"text":"impl Error for ParkError","synthetic":false,"types":[]}];
implementors["tokio_timer"] = [{"text":"impl&lt;T:&nbsp;StdError + 'static&gt; Error for ThrottleError&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;Error&gt; Error for Error&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl Error for Error","synthetic":false,"types":[]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()