# cryptohash

## Introduction to MD5

https://blog.csdn.net/u012611878/article/details/54000607

## Optimization Strategies

A reference: Design and Optimizations of the MD5 Crypt Cracking Algorithm Based on CUDA, Renjie Chen

1. Global memory access coalescing

2. Shared memory, locality of MD5 hash for test

3. Stream Optimizations, to launch multiple kernal simultaneously. Each kernel calculates one type of string length

4. Try different grid size and block size.

5. Optimize for the resource available.

6. Constant memory for initial values in MD5.