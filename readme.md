<h1 align="center">
  <a href="https://captaincore.io"><img src="https://captaincore.io/wp-content/uploads/2018/02/main-web-icons-captain.png" width="70" /></a><br />
CaptainCore Dispatch Server

</h1>

CaptainCore Dispatch is a Golang web server part of the [CaptainCore](https://captaincore.io) toolkit. It handles communication between [CaptainCore](https://github.com/captaincore/captaincore-gui) and [CaptainCore CLI](https://github.com/captaincore/captaincore-cli).

[![emoji-log](https://cdn.rawgit.com/ahmadawais/stuff/ca97874/emoji-log/flat.svg)](https://github.com/ahmadawais/Emoji-Log/)

## **Warning**
This project is under active development and **not yet stable**. Things may break without notice. Only proceed if your wanting to spend time on the project. Sign up to receive project update at [captaincore.io](https://captaincore.io/).

## Getting started

TO DO

## Local development setup

You can run CaptainCore Dispatch locally for development or testing purposes. This requires the following.


- Install CaptainCore CLI locally
- Install CaptainCore on a WordPress site locally

### Setup instructions

- Clone the git repo.
- Create `config.json` file with
```
{
    "tokens": [
        {
            "captain_id":"1",
            "token":"RANDOM_TOKEN_CHANGE_ME"
        },
     ],
    "host":"localhost:5826",
    "port":"5826",
    "ssl_mode":"development"
}
```
- Use Go to compile and run the server. 
```
go run captaincore-dispatch.go server --debug
```
- Import freshly generated CA key `certs/ca.crt` into computer/browser.
- Configure local WordPress site running CaptainCore with the token key used within Dispatch `config.json`. This allows

## License
This is free software under the terms of MIT the license (check the LICENSE file included in this package).
