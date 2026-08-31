# Math Curve Loaders

[Live Preview](https://paidax01.github.io/math-curve-loaders/)

A lightweight mathematical-curve loading indicator used by NumericalOJ.

Loading placement follows two rules:

- page loading renders directly in the current page region
- component loading renders inside the component or its triggering control
- loading never creates a backdrop or modal

## Files

- `loader.css`: inline page/component loader styles
- `loader.js`: curve renderer and local request-state helpers

## Run

The application loads both files from `frontend/index.html`.

## Why

This project explores how mathematical parameterizations can become expressive UI loading states while staying lightweight and dependency-free.
