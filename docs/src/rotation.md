# Rotation

```admonish warning
This feature is not yet implemented.

If you like, you can have a look at the plan to implement it [here](https://github.com/open-sesam/sesam/issues/40).
```


From our experience, the biggest security threat are not holes in the software
itself, but social factors. Colleagues leaving the company for example could
still have a local copy of all secrets. While you will 99% of the time leave
always on good terms you still have to consider those secrets as lost for the
other 1%.

```admonish note
We use those terms:

**rotate:** Replace a secret with a new secret of the same format.
For example, an old password is replaced with a new one.

**swap:** Replace a rotated secret at the place where it was used.
For example, an ssh key that was rotated needs to be changed in *authorized_keys*.
```

In reality there is therefore no way to not rotate and swap secrets from time to time. We gave `sesam` therefore features that help with automating this tedious process.

