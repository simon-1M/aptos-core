
# Run all benches

```bash
bash generate-bench-data.sh
```

# Parse bench data

## All data

```bash
bash generate-gas-csv.sh outputs
```

## Single data

```bash
bash parse-bench.sh bls12381 aggregate_pks/1024

bash parse-hash-benches.sh  Keccak-256 outputs/keccak-256.out
```