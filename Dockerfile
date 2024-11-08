FROM scratch
COPY stash /bin/stash
ENTRYPOINT ["/bin/stash"]
