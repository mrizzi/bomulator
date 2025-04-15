# BOMulator

**BOMulator** is a synthetic Bill of Materials (BOMs) — currently SBOM — simulator for testing, analysis, and research. Whether you're simulating large software supply chains or stress-testing your SBOM ingestion pipeline, BOMulator helps you create tailor-made BOMs that match your needs.

---

## Features

- Generate **synthetic SBOMs** with **customizable number of vulnerabilities and package types** (e.g. Maven, crates.io, Golang, Pypi, etc)
- Ingest and parse vulnerability data from [OSV](https://osv.dev)
- [_Soon_] Store structured vulnerability data into a PostgreSQL database

---

## Usage

You need to have installed [Docker](https://docs.docker.com/engine/install/) or [Podman](https://podman.io/docs/installation).

1. Download the OSV data in the way you prefer among:
   1. With a browser download https://osv-vulnerabilities.storage.googleapis.com/all.zip
   2. From a terminal, execute
       ```shell
       curl -O https://osv-vulnerabilities.storage.googleapis.com/all.zip
       ```
2. Run BOMulator using container (you can replace `podman` with `docker`)
   ```shell
   podman run -v ./:/bomulator:Z quay.io/mrizzi/bomulator:latest -i /bomulator/all.zip -o /bomulator/
   ```
   and you should get an output like:
   ```shell
   Input zip file ingestion
   Output file data gathering
   Created files:
   /bomulator/bomulator-0.1.0-e3b9ad9c-2a58-40fc-8fae-7aaa4baa7d5a.cdx.json
   /bomulator/bomulator-0.1.0-e3b9ad9c-2a58-40fc-8fae-7aaa4baa7d5a.spdx.json
   ```
   
In your local directory the two newly generated SBOMs will be available.

### Input options

The available input options can be retrieved running:

```
podman run quay.io/mrizzi/bomulator:latest
```

---

## Contributing

Pull requests and feedback are welcome! Please open an issue first to discuss major changes.

---

## Roadmap

Check the open issues for the list of upcoming changes: please vote the ones you need/like the most, thank you.
