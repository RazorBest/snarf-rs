# Development

## Prek for pre-commit

Install prek on your development machine:
```
cargo install --locked prek
```
Or use one of the methods listed here: https://github.com/j178/prek.

Add it to your git hooks:
```
prek install
```

Now, it will be run before every commmit. If you wish to run prek manually,
you can do `prek run`.
