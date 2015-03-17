Package goji-auth
=================

`goji-auth` provides an easy and simple solution to use a basic HTTP Auth. 
You need to know, beforehand, that Basic Auth is considered insecure because 
both the username and password are encoded and not encrypted (meaning, 
anyone with enough knowlegde could retrieve them easily), so it's important
to put the website where you're going to use your password under an SSL 
connection to prevent eavesdropping.

This package only works with the [Goji package](https://github.com/zenazn/goji)
and not plain `net/http`. There are several packages to use with a plain `net/http`
setup. You could also use it with the [cji package](https://github.com/pressly/cji)
so you can mix and match it with your routes.


### Normal usage

There are two options to use this package. The first one is to use the short version
called `WithUserPass` where you can pass an username and a password. The second option
is to use the longer version with a custom configuration, which, along with an username 
and a password, you could also change the Auth message presented by certain browsers to 
the user. 

```golang
	// Short option, where the message is "Protected" 
	// and the Error message is "Unauthorized"
	a := auth.Auth(auth.WithUserPass("user", "pass"))

	// Semi-short option where you can set-up the 
	// Message prompted to the user is configurable
	a = auth.Auth(auth.WithUserPassMessage("user", "pass", "This is a Custom Message"))

	// Last option is to fully personalize the
	// data, like this...
	a = auth.Auth(auth.AuthConfig{
		Username: "user",
		Password: "pass",
		Message: "Admin Panel",
		UnauthorizedMessage: "You're not authorized to log in",
	})

	// Later, on your code, you could pass it to the
	// goji.Use() function
	goji.Use(a)
```

### Usage with plain Goji

```golang
	goji.Use(auth.Auth(auth.WithUserPass("user", "pass")))
	goji.Serve()
```

### Usage with cji

```golang
	authControl := auth.Auth(auth.WithUserPass("user", "pass"))
	goji.Get("/", cji.Use(authControl).On(myhandler))
```