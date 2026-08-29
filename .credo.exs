%{
  configs: [
    %{
      name: "default",
      strict: true,
      checks: %{
        extra: [
          # TCP fixture values are clearer in the decimal form used by the wire format.
          {Credo.Check.Readability.LargeNumbers,
           files: %{excluded: ["test/**/*.{ex,exs}"]}}
        ]
      }
    }
  ]
}
