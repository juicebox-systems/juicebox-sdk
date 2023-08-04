#let whitepaper(
  title: [],
  subtitle: [],
  abstract: [],
  authors: (),
  date: none,
  version: none,
  bibliography-file: none,
  body,
) = {
  // Set the document's basic properties.
  set document(author: authors.map(a => a.name), title: title)
  set page(paper: "us-letter", numbering: "1", number-align: center)
  set text(font: "Linux Libertine", lang: "en")
  set heading(numbering: "1.1")

  // Configure citation and bibliography styles.
  set cite(style: "numerical", brackets: true)
  set bibliography(style: "ieee", title: none)

  // Configure equations
  show math.equation: set text(style: "italic")

  set enum(indent: 1.5em)
  set list(indent: 1.5em)
  set terms(separator: [*:* ])

  v(8em)

  // Title row.
  align(center)[
    #text(weight: 500, 1.75em, title)
    #v(1.2em, weak: true)
    #text(1.2em, subtitle)
    #v(2em, weak: true)
    #version — #date
  ]

  // Author information.
  pad(
    top: 0.5em,
    x: 2em,
    grid(
      columns: (1fr,) * calc.min(3, authors.len()),
      gutter: 1em,
      ..authors.map(author => align(center)[
        #author.name \
        #author.affiliation
      ]),
    ),
  )

  v(8em)

  set par(justify: true)

  align(center)[
    *Abstract*
  ]

  abstract

  pagebreak()

  outline(indent: true)

  pagebreak()

  // Main body.

  body

  // Display the bibliography, if any is given.
  if bibliography-file != none {
    show bibliography: set text(8.5pt)
    show bibliography: pad.with(x: 0.5pt)
    bibliography(bibliography-file)
  }
}
