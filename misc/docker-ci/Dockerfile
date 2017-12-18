FROM kazuho/h2o-ci:latest

# copy files
COPY . h2o
RUN sudo chown -R ci:ci h2o
WORKDIR h2o

CMD ["make", "-f", "misc/docker-ci/check.mk"]
