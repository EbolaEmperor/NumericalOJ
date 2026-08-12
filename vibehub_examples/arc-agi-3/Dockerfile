FROM numericaloj-vibehub-runtime:1

COPY --chown=65532:65532 . /app
RUN python /app/app.py --precompute

CMD ["python", "/app/app.py"]
