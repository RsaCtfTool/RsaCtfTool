# Changelog

## Commit from 14/04/2020

### Massive code reorganization and additions

- Attacks against single key are stored in  `/attacks/single_key` folder;
- Attacks against multiple keys are stored in  `/attacks/multi_key` folder;
- Attacks are dynamically loaded;
- RsaCtfTool core is moved into `/lib` folder;
- Sage scripts are moved in `/sage` folder;
- RsaCtfTool.py is just an cli parser / some output implemented. No more logic inside;
- Multi ciphers support;
- black formatting;
- New attacks : londahl and qicheng;
- `--dumpkey` and `--ext` now dump informations about each keys (public and private).

### New tests in test.sh

- Hastads;
- Unciphering multiple files;
- Testing multiple keys against on cipher;
- Extra informations output.

### Fixes

- Multiple attacks are fixed;
- Better exceptions handling;
- Code cleaning;
- Fix a lot of tests.

### How to add new attacks

New RsaCtfTool architecture improve code readability and extensibility.

#### Adding single key attack

If you want to add an attack against a single key, just add a new file into `/attacks/single_key/attack_name.py` with an attack method.
Example :

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

def attack(attack_rsa_obj, publickey, cipher=[]):
    # Code logic here
    return (None, None)
```

- attack_rsa_obj : a reference to `lib.rsa_attack.RSAAttack` instance. it gave access to cli arguments and various informations;
- publickey : a `lib.keys_wrapper.PublicKey` instance;
- cipher : a list containing each data to uncipher.

The attack method return a tuple :
(`private_key`, `unciphered_data`)

- private_key : an instance of `lib.keys_wrapper.PrivateKey` if recovered, else None. If multiple keys are recovered, return a `list` of `lib.keys_wrapper.PrivateKey`;
- unciphered_data : if the attack focus on unciphering and not private key retreiving. If the private key is recovered, just return `None` and it will be deciphered later in script. If no data is recovered, return `None`. If multiple ciphers are recovered, return a `list` of `bytes`.

#### Adding multiple keys attack

If you want to add an attack against multiple keys, just add a new file into `/attacks/multi_key/attack_name.py` with an attack method.
Example :

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

def attack(attack_rsa_obj, publickeys, cipher=[]):
    # Code logic here
    return (None, None)
```

- attack_rsa_obj : a reference to `lib.rsa_attack.RSAAttack` instance. it gave access to cli arguments and various informations;
- publickeys : a list of `lib.keys_wrapper.PublicKey` instance;
- cipher : a list containing each data to uncipher.

The attack method return a tuple :
(`private_key`, `unciphered_data`)

- private_key : an instance of `lib.keys_wrapper.PrivateKey` if recovered, else None. If multiple keys are recovered, return a `list` of `lib.keys_wrapper.PrivateKey`;
- unciphered_data : if the attack focus on unciphering and not private key retreiving. If the private key is recovered, just return `None` and it will be deciphered later in script. If no data is recovered, return `None`. If multiple ciphers are recovered, return a `list` of `bytes`.

## Ending note

Still beerware licensed :)
Test, make pull requests (and issues) and add new attacks !
Keep safe & stay at home folks !
