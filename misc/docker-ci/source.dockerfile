FROM h2o-ci-base

# copy files
COPY . h2o
RUN sudo chown -R ci:ci h2o
WORKDIR h2o
