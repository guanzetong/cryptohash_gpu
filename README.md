# Cryptohash on GPU

## Build

```
module load cuda
./build cryptohash.cu md5
```

## Run kernel

`sbatch run_test [32-character hash]`