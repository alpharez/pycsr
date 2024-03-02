# pycsr

## installing dependencies

pip install pyyaml
pip install cryptography

## creating a CSR

edit csr.yaml with SSL info.  Alternate (SAN) names can be listed under 'sans'.

```
sans:
  - name: www.example.com
  - name: web.example.com
```

python csr.py

Output is the key and csr in PEM format.
