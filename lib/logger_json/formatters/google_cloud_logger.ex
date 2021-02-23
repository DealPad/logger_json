defmodule LoggerJSON.Formatters.GoogleCloudLogger do
  @moduledoc """
  Google Cloud Logger formatter.
  """
  import Jason.Helpers, only: [json_map: 1]

  alias LoggerJSON.{FormatterUtils, JasonSafeFormatter}

  @behaviour LoggerJSON.Formatter

  @processed_metadata_keys ~w[pid file line function module application]a

  # Severity levels can be found in Google Cloud Logger docs:
  # https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry#LogSeverity
  @severity_levels [
    {:debug, "DEBUG"},
    {:info, "INFO"},
    {:warn, "WARNING"},
    {:error, "ERROR"}
  ]

  @doc """
  Builds structured payload which is mapped to Google Cloud Logger
  [`LogEntry`](https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry) format.

  See: https://cloud.google.com/logging/docs/agent/configuration#special_fields_in_structured_payloads
  """
  for {level, gcp_level} <- @severity_levels do
    def format_event(unquote(level), msg, ts, md, md_keys) do
      Map.merge(
        %{
          time: FormatterUtils.format_timestamp(ts),
          severity: unquote(gcp_level),
          message: IO.chardata_to_string(msg)
        },
        format_metadata(md, md_keys)
      )
    end
  end

  def format_event(_level, msg, ts, md, md_keys) do
    Map.merge(
      %{
        time: FormatterUtils.format_timestamp(ts),
        severity: "DEFAULT",
        message: IO.chardata_to_string(msg)
      },
      format_metadata(md, md_keys)
    )
  end

  defp format_metadata(md, md_keys) do
    LoggerJSON.take_metadata(md, md_keys, @processed_metadata_keys)
    |> JasonSafeFormatter.format()
    |> FormatterUtils.maybe_put(:error, FormatterUtils.format_process_crash(md))
    |> FormatterUtils.maybe_put(:"logging.googleapis.com/sourceLocation", format_source_location(md))
    |> FormatterUtils.maybe_put(:"logging.googleapis.com/operation", format_operation(md))
    |> FormatterUtils.maybe_put(:"logging.googleapis.com/trace", format_trace(md))
    |> FormatterUtils.maybe_put(:"logging.googleapis.com/span", format_span(md))
  end

  defp format_operation(md) do
    if request_id = Keyword.get(md, :request_id) do
      json_map(id: request_id)
    end
  end

  # Description can be found in Google Cloud Logger docs;
  # https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry#LogEntrySourceLocation
  defp format_source_location(metadata) do
    file = Keyword.get(metadata, :file)
    line = Keyword.get(metadata, :line, 0)
    function = Keyword.get(metadata, :function)
    module = Keyword.get(metadata, :module)

    json_map(
      file: file,
      line: line,
      function: FormatterUtils.format_function(module, function)
    )
  end

  # Description can be found in Google Cloud Logger docs;
  # https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry#FIELDS.trace
  defp format_trace(metadata) do
    Keyword.get(metadata, :trace)
  end

  # Description can be found in Google Cloud Logger docs;
  # https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry#FIELDS.span_id
  defp format_span(metadata) do
    Keyword.get(metadata, :span_id)
  end
end
