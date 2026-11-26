FROM registry.fedoraproject.org/fedora:44

RUN dnf install -y ca-certificates curl unzip && dnf clean all

ENV JAVA_HOME=/opt/jdk21
ENV PATH=/opt/jdk21/bin:$PATH

RUN curl -fsSL -o /tmp/jdk21.tar.gz \
        "https://api.adoptium.net/v3/binary/version/jdk-21.0.12.1%2B1/linux/x64/jdk/hotspot/normal/eclipse" \
    && echo "ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94  /tmp/jdk21.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/jdk21.tar.gz -C /opt \
    && mv /opt/jdk-21.0.12.1+1 /opt/jdk21 \
    && rm -f /tmp/jdk21.tar.gz

RUN curl -fsSL -o /tmp/ghidra.zip \
        "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.3_build/ghidra_12.1.3_PUBLIC_20260817.zip" \
    && echo "93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54  /tmp/ghidra.zip" | sha256sum -c - \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_12.1.3_PUBLIC /opt/ghidra \
    && rm -f /tmp/ghidra.zip

COPY build/processor/ /opt/ghidra/Ghidra/Processors/iRISC/

RUN cd /opt/ghidra/Ghidra/Processors/iRISC/data \
    && /opt/jdk21/bin/java -Xmx2048M \
        -cp "/opt/ghidra/Ghidra/Framework/SoftwareModeling/lib/*:/opt/ghidra/Ghidra/Framework/Generic/lib/*:/opt/ghidra/Ghidra/Framework/Utility/lib/*" \
        ghidra.pcodeCPort.slgh_compile.SleighCompile -DBaseDir=/opt/ghidra/ -i sleighArgs.txt -a ./languages \
    && test -f /opt/ghidra/Ghidra/Processors/iRISC/data/languages/iRISC.sla

COPY scripts/ghidra/ /opt/ghidra/Ghidra/Features/Base/ghidra_scripts/

COPY docker/ghidra-decode.sh /usr/local/bin/ghidra-decode

COPY docker/ghidra-re.sh /usr/local/bin/ghidra-re

ENTRYPOINT ["/usr/local/bin/ghidra-decode"]

WORKDIR /work
