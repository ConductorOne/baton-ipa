FROM gcr.io/distroless/static-debian11:nonroot
ENTRYPOINT ["/baton-ipa"]
COPY baton-ipa /