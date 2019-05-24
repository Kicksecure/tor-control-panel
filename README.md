# Tor Control Graphical User Interface #

tor-control-panel is a Tor controller.

tor-control-panel is produced independently from the Tor anonymity
software and carries no guarantee from The Tor Project about quality,
suitability or anything else.
## How to install `tor-control-panel` using apt-get ##

1\. Add [Whonix's Signing Key](https://www.whonix.org/wiki/Whonix_Signing_Key).

```
sudo apt-key --keyring /etc/apt/trusted.gpg.d/whonix.gpg adv --keyserver hkp://ipv4.pool.sks-keyservers.net:80 --recv-keys 916B8D99C38EAF5E8ADC7A2A8D66066A2EEACCDA
```

3\. Add Whonix's APT repository.

```
echo "deb http://deb.whonix.org buster main contrib non-free" | sudo tee /etc/apt/sources.list.d/whonix.list
```

4\. Update your package lists.

```
sudo apt-get update
```

5\. Install `tor-control-panel`.

```
sudo apt-get install tor-control-panel
```

## How to Build deb Package ##

Replace `apparmor-profile-torbrowser` with the actual name of this package with `tor-control-panel` and see [instructions](https://www.whonix.org/wiki/Dev/Build_Documentation/apparmor-profile-torbrowser).

## Contact ##

* [Free Forum Support](https://forums.whonix.org)
* [Professional Support](https://www.whonix.org/wiki/Professional_Support)

## Donate ##

`tor-control-panel` requires [donations](https://www.whonix.org/wiki/Donate) to stay alive!
