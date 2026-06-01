# Re:Small d - AlpacaHack Challenge - Boneh-Durfee Attack

## Problem Overview

We are given a script (`prob.py`) that generates an RSA key pair and encrypts a flag. 
Looking at the source code, the prime generation is standard ($p$ and $q$ are 512 bits, making $N$ a 1024-bit modulus). However, the vulnerability lies in how the private exponent, $d$, is selected:

```python
d = getPrime(275)  # n^0.25 < d < n^0.292
```

The script explicitly forces the private key $d$ to be a 275-bit prime. Since a standard 1024-bit RSA key usually has a $d$ of similar bit-length to $N$ (around 1024 bits), a 275-bit $d$ is extremely small and opens the door to partial key exposure attacks.

## Why Wiener's Attack Fails

When encountering a "small $d$" RSA challenge, the first instinct is usually to try **Wiener's Attack**.

Wiener's attack utilizes continued fractions to recover the private key, but it has a strict mathematical limitation. It only works if $d$ satisfies the following bound:


$$d < \frac{1}{3} N^{0.25}$$

Let's look at the bit-lengths in our challenge:

* **$N$ bit-length:** 1024 bits
* **Wiener's maximum $d$ bit-length:** $\approx 1024 \times 0.25 = 256$ bits.
* **Actual $d$ bit-length:** 275 bits.

Because $275 > 256$, $d$ is strictly greater than $N^{0.25}$. Therefore, Wiener's attack will fail to find the correct fractions, making it useless for this specific challenge.

## The Solution: Boneh-Durfee Attack

To break this, we must use the **Boneh-Durfee attack**. In 1999, Dan Boneh and Glenn Durfee published an improvement over Wiener's result using Coppersmith's method for finding small roots of modular polynomial equations using lattice reduction (LLL).

The Boneh-Durfee attack extends the theoretical bound of a vulnerable $d$ up to:


$$d < N^{0.292}$$

* **Boneh-Durfee maximum $d$ bit-length:** $\approx 1024 \times 0.292 = 299$ bits.

Since our $d$ is 275 bits, it falls perfectly within the $N^{0.25} < d < N^{0.292}$ window, making it the exact target for this attack.

## Implementation Details

To execute the attack, we used David Wong's implementation of the Boneh-Durfee attack in SageMath (`boneh_durfee.sage`).

https://raw.githubusercontent.com/mimoo/RSA-and-LLL-attacks/refs/heads/master/boneh_durfee.sage

### Script Modifications

We modified the `example()` function in `boneh_durfee.sage` to include our specific challenge parameters:

1. **Inserted the Target Data:** Added the extracted `N`, `e`, and `c` values from the challenge output.
2. **Tuned the bounds (`delta`):** The attack requires a $\delta$ parameter such that $d < N^{\delta}$. We set `delta = .27` because $\frac{275}{1024} \approx 0.268$, which is comfortably below 0.27.
3. **Set the lattice dimension (`m`):** We set `m = 5` which defines the size of the lattice. A larger `m` makes the algorithm slower but more accurate; `5` was sufficient here.
4. **Added Decryption Logic:** Once $d$ is recovered, the script automatically decrypts the ciphertext $c$ and parses the bytes to print the flag:

```python
m = pow(c, d, N)
print(int(m).to_bytes((int(m).bit_length() + 7) // 8, 'big').decode(errors='ignore'))

```

### Execution & Output

Running the modified script in SageMath optimizes the lattice basis via LLL and successfully extracts the private key in less than 2 seconds:

```console
$ sage boneh_durfee.sage
=== checking values ===
* delta: 0.270000000000000
* delta < 0.292 True
* size of e: 1022
* size of N: 1022
* m: 5 , t: 2
=== running algorithm ===
...
optimizing basis of the lattice via LLL, this can take a long time
LLL is done!
looking for independent vectors in the lattice
found them, using vectors 0 and 1
=== solution found ===
private key found: 50477050438877441127392288882379116831734203546321894296597963461964771668720521089
Alpaca{Re:small_d_is_too_dangerous_for_rsa!!!!!!}
=== 1.3869085311889648 seconds ===

```

**Flag:** `Alpaca{Re:small_d_is_too_dangerous_for_rsa!!!!!!}`
