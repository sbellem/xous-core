# Why Guix?

_By Claude, who makes stuff up ..._

Guix provides reproducible, bit-for-bit identical builds by treating every package and its dependencies as immutable, content-addressed store items. For security-critical projects like xous-core, this means anyone can verify they're running the exact same code the developers built—no hidden modifications, no dependency confusion, no "works on my machine." Combined with Guix's transparent bootstrapping (the entire package graph of 22,000+ packages is rooted in a [357-byte auditable program][full-source-bootstrap]), it offers the strongest available guarantees that what you audit is what you run.

## Key Principles

**Reproducibility through functional package management:**

> "Guix builds upon the *functional package management* paradigm. The idea is to view package build processes as *pure functions*: given a set of inputs—compilers, libraries, build scripts, and source code—a package's build process is assumed to always produce the same result."
>
> — Courtès & Wurmus, [*Reproducible and User-Controlled Software Environments in HPC with Guix*][courtes2015] (2015)

**Auditability through bit-reproducibility:**

> "This approach provides *bit-reproducibility*: building a given package with a given set of inputs is expected to always produce the exact same result, bit for bit. This property is crucial for *auditability*: it allows independent parties to *verify* that a given binary blob does match the alleged source code."
>
> — Courtès & Wurmus, [*Reproducible and User-Controlled Software Environments in HPC with Guix*][courtes2015] (2015)

**Bootstrappability against supply-chain attacks:**

> "If you think one should always be able to build software from source, then it follows that the 'trusting trust' attack is only a symptom of an incomplete or missing bootstrap story."
>
> — [*The Full-Source Bootstrap: Building from source all the way down*][full-source-bootstrap] (2023)

> "Every unauditable binary leaves us vulnerable to compiler backdoors as described by Ken Thompson in the 1984 paper *Reflections on Trusting Trust*."
>
> — [*Guix Reduces Bootstrap Seed by 50%*][bootstrap-50] (2019)

**Trust through transparency:**

> "To gain trust in our computing platforms, we need to be able to tell how each part was produced from source, and opaque binaries are a threat to user security and user freedom since they are not auditable."
>
> — Jan Nieuwenhuizen, [Reproducible Builds interview][janneke-interview] (2022)

## References

### Academic Papers

- Courtès, L., & Wurmus, R. (2015). *Reproducible and User-Controlled Software Environments in HPC with Guix*. Euro-Par 2015: Parallel Processing Workshops. https://arxiv.org/abs/1506.02822

- Wurmus, R., Uyar, B., Osberg, B., Franke, V., Gosdschan, A., Wreczycka, K., Ronen, J., & Akalin, A. (2018). *Reproducible genomics analysis pipelines with GNU Guix*. GigaScience, 7(12). https://doi.org/10.1093/gigascience/giy123

- Vallet, N., Michonneau, D., & Tournier, S. (2022). *Toward practical transparent verifiable and long-term reproducible research using Guix*. Scientific Data, 9, 597. https://doi.org/10.1038/s41597-022-01720-9

### Guix Blog Posts

- [The Full-Source Bootstrap: Building from source all the way down][full-source-bootstrap] (2023)
- [Guix Further Reduces Bootstrap Seed to 25%][bootstrap-25] (2020)
- [Guix Reduces Bootstrap Seed by 50%][bootstrap-50] (2019)

### External Resources

- [GNU Guix Publications][guix-publications]
- [Reproducible Builds Project][reproducible-builds]
- [Bootstrappable Builds Project][bootstrappable]

[courtes2015]: https://arxiv.org/abs/1506.02822
[full-source-bootstrap]: https://guix.gnu.org/en/blog/2023/the-full-source-bootstrap-building-from-source-all-the-way-down/
[bootstrap-50]: https://guix.gnu.org/blog/2019/guix-reduces-bootstrap-seed-by-50/
[bootstrap-25]: https://guix.gnu.org/en/blog/2020/guix-further-reduces-bootstrap-seed-to-25/
[janneke-interview]: https://reproducible-builds.org/news/2022/05/18/jan-nieuwenhuizen-on-bootrappable-builds-gnu-mes-and-gnu-guix/
[guix-publications]: https://guix.gnu.org/en/publications/
[reproducible-builds]: https://reproducible-builds.org/
[bootstrappable]: https://bootstrappable.org/
