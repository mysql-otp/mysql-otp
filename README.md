MySQL/OTP
=========

This is a MySQL driver for Erlang following the OTP principles.

Status: Just started. Connecting works but nothing else.

Background: We are starting this project with the aim at overcoming the problems with Emysql (the currently most popular driver) and erlang-mysql-driver (the even older driver).

Design choices (ideas):

* A connection is a gen_server.
* No connection pool. Poolboy or your own supervisor can be used for this.
* No records in the public API.
* API inspired by that of epgsql (the PostgreSQL driver).

Contributing
------------

We welcome contributors and new members of the project. We are open for suggestions about the API, the internal design and almost anything else. Let's use the project's wiki for discussions and TODOs.

Problems with Emysql
--------------------

From the Emysql README:

> The driver has several technical shortcomings:
>
> * No clear protocol / connection pool separation
> * No clear protocol / socket separation
> * A very complicated connection pool management
> * Uses the textual protocol in a lot of places where it shouldthe binary protocol
> * The API could be better
>
>However, this is probably the best MySQL driver out there for Erlang. The erlang-mysql-driver uses a problematic connection pool design for many use cases and is not suitable for general purpose use. This driver is.
