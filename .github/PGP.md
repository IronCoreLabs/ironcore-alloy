# PGP key

The PGP key in this directory needs to be stored without a passphrase
protecting it. This is difficult to do. You can try to remove the passphrase
from an existing keyring following
https://superuser.com/questions/1360324/gpg-remove-passphrase or other
instructions, or you can update this key in place using these instructions:

1. Create a clean GPG environment. You can blow away your `.gnupg` directory,
    or you can run `docker run -it --rm -v $(pwd):/src alpine`.
1. Import the existing keyring from `gdrive/IronCore Engineering/IT_Info/pgp`.
    You'll need the passphrase which is stored there.
1. Update the expiration dates using `gpg --edit-key 9FA43559`.
1. Upload the modified key using `gpg --send-keys 9FA43559`. You may want to
    send it to multiple keyservers, because they don't talk to each other very
    reliably. Consider using keys.gnupg.net, pool.sks-keyservers.net,
    and keyserver.ubuntu.com.
1. Throw away your clean GPG environment and make a new clean GPG environment.
1. `ironhide file decrypt 9FA43559.asc.iron`
1. `gpg --import 9FA43559.asc`
1. `gpg --recv-keys 9FA43559`. If you have trouble with this, try an alternate
    keyserver from the list above that you pushed the modified key to.
1. `gpg --export-secret-keys -a > 9FA43559.asc`
1. Exit your clean GPG environment.
1. `rm 9FA43559.asc.iron`
1. `ironhide file encrypt -g ICL-ops -u ops@ironcorelabs.com 9FA43559.asc`
