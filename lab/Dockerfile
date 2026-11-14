# A disposable Rocky 9 box to practice on. sshd only, bound to localhost by
# run.sh. plant.sh then recreates the red team kit's footprints with
# harmless stand-ins (copies of bash and sleep, not real implants).
FROM rockylinux:9
RUN dnf -y install openssh-server openssh-clients python3 procps-ng cronie e2fsprogs \
 && dnf clean all \
 && ssh-keygen -A \
 && mkdir -p /root/.ssh && chmod 700 /root/.ssh
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
