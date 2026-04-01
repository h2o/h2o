#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "jrf"
require "open3"
require "optparse"
require "time"

SIMULATOR = File.join(ENV.fetch("BINARY_DIR", "."), "simulator")

NETWORKS = {
  "DSL" => { rtt: 0.03, queue: 0.05, bw: 30e6 },
  "Home_WiFi" => { rtt: 0.025, queue: 0.015, bw: 100e6 },
  "Public" => { rtt: 0.04, queue: 0.2, bw: 20e6 },
  "Corporate_WiFi" => { rtt: 0.01, queue: 0.02, bw: 500e6 },
  "LTE" => { rtt: 0.06, queue: 0.12, bw: 30e6 },
  "5G" => { rtt: 0.04, queue: 0.08, bw: 100e6 },
  "LEO" => { rtt: 0.04, queue: 0.08, bw: 50e6 },
  "GEO" => { rtt: 0.6, queue: 0.6, bw: 50e6 },
  "DoCoMo@Office" => { rtt: 0.028, queue: 0.245 - 0.028, bw: 140e6 },
  "au@Office" => { rtt: 0.02, queue: 0.253 - 0.02, bw: 440e6 },
  "WiFi@Office" => { rtt: 0.004, queue: 0.015 - 0.004, bw: 710e6 },
  "DoCoMo@mall" => { rtt: 0.041, queue: 0.341 - 0.041, bw: 38e6 },
  "congested" => { rtt: 0.2, queue: 0.4, bw: 1e6 },
  "bdp20" => { rtt: 0.1, queue: 0.1, bw: 1e6 },
  "bdp40" => { rtt: 0.1, queue: 0.1, bw: 2e6 }
}.freeze

def parse_flows(tokens)
  flows = []
  while tokens.any?
    label = tokens.shift
    raise ArgumentError, "missing flow label" if label.nil? || label.empty?

    flow_opts = []
    flow_opts << tokens.shift while tokens.any? && tokens[0] != "--"
    flows << [label, flow_opts]
    tokens.shift if tokens[0] == "--"
  end
  flows
end

def parse_simulator_output(lines)
  Enumerator.new do |y|
    lines.each do |line|
      begin
        y << JSON.parse(line)
      rescue JSON::ParserError
        next
      end
    end
  end
end

def build_values(events, labels, show_queue)
  src_to_label = {}
  next_label_index = 0

  assign_label = lambda do |src|
    return nil if src.nil?
    return src_to_label[src] if src_to_label.key?(src)
    return nil if next_label_index >= labels.length

    label = labels[next_label_index]
    src_to_label[src] = label
    next_label_index += 1
    label
  end

  Jrf.new(
    proc do
      select(
        _.key?("bytes-available") ||
        (show_queue && (_["bottleneck"] == "enqueue" || _["bottleneck"] == "dequeue"))
      )
    end,
    proc do
      if _.key?("bytes-available")
        flow = labels.length == 1 ? labels[0] : assign_label.call(_["packet-src"])
        if flow.nil?
          select(false)
        else
          _.merge("flow" => flow, "kind" => "deliver")
        end
      else
        _.merge("flow" => labels[0], "kind" => "queue")
      end
    end,
    proc do
      {
        "at" => _["at"] - 1000.0,
        "value" => _["kind"] == "deliver" ? _["bytes-available"] : _["queue-size"],
        "flow" => _["flow"],
        "metric" => _["kind"]
      }
    end,
    proc { sort([_["at"], _["flow"], _["metric"]]) }
  ).call(events)
end

def build_spec(values:, length:, title:, show_queue:, width:, height:, flow_count:)
  x_encoding = {
    "field" => "at",
    "type" => "quantitative",
    "title" => "time (s)",
    "scale" => { "domain" => [0, length] }
  }

  layers = [
    {
      "transform" => [{ "filter" => "datum.metric == 'deliver'" }],
      "mark" => { "type" => "line" },
      "encoding" => {
        "x" => x_encoding,
        "y" => {
          "field" => "value",
          "type" => "quantitative",
          "title" => "bytes available"
        }
      }
    }
  ]

  if show_queue
    metric_color = {
      "field" => "metric",
      "type" => "nominal",
      "title" => "metric",
      "scale" => {
        "domain" => ["deliver", "queue"],
        "range" => ["#1f77b4", "#d62728"]
      }
    }
    layers[0]["encoding"]["color"] = metric_color
    if flow_count > 1
      flow_dash = {
        "field" => "flow",
        "type" => "nominal",
        "title" => "flow"
      }
      layers[0]["encoding"]["strokeDash"] = flow_dash
    end

    layers << {
      "transform" => [{ "filter" => "datum.metric == 'queue'" }],
      "mark" => { "type" => "line", "interpolate" => "step-after" },
      "encoding" => {
        "x" => x_encoding,
        "y" => {
          "field" => "value",
          "type" => "quantitative",
          "axis" => { "title" => "queue size (bytes)", "orient" => "right" }
        },
        "color" => metric_color
      }
    }
    if flow_count > 1
      layers[1]["encoding"]["strokeDash"] = {
        "field" => "flow",
        "type" => "nominal",
        "title" => "flow"
      }
    end
  else
    if flow_count > 1
      layers[0]["encoding"]["color"] = {
        "field" => "flow",
        "type" => "nominal",
        "title" => "flow"
      }
    else
      layers[0]["mark"]["color"] = "#1f77b4"
    end
  end

  spec = {
    "$schema" => "https://vega.github.io/schema/vega-lite/v5.json",
    "title" => title,
    "width" => width,
    "height" => height,
    "data" => { "values" => values },
    "layer" => layers
  }
  spec["resolve"] = { "scale" => { "y" => "independent" } } if show_queue
  spec
end

def render_svg(spec_json, svg_path)
  stdout, stderr, status = Open3.capture3("vl2svg", stdin_data: spec_json)
  raise "renderer failed: #{stderr.strip}" unless status.success?
  raise "renderer did not produce SVG output" if stdout.nil? || stdout.empty?

  File.write(svg_path, stdout)
rescue Errno::ENOENT
  warn "renderer not found on PATH."
  warn "Either 'vl2svg' is not installed, or your PATH is not set up to include it."
  warn "Install with one of:"
  warn "  npm install -g vega-lite vega-cli"
  warn "  npm install vega-lite vega-cli"
  warn "Then verify with: command -v vl2svg"
  warn "or run without rendering: --no-render"
  exit 2
end

cc = "pico"
length = 1.0
network_name = "DSL"
show_queue = false
output_prefix = "simulator"
render = true
auto_open = true
width = 1000
height = 1000
title_override = nil

sep_index = ARGV.index("--")
global_argv = sep_index ? ARGV[0...sep_index] : ARGV.dup
flow_argv = sep_index ? ARGV[(sep_index + 1)..] : []

OptionParser.new do |opt|
  opt.on("-c NAME") { |v| cc = v }
  opt.on("--length=SECONDS", Float) { |v| length = v }
  opt.on("--network=NAME") do |v|
    raise OptionParser::InvalidArgument, "unknown network: #{v}" unless NETWORKS.key?(v)

    network_name = v
  end
  opt.on("--queue") { show_queue = true }
  opt.on("--output=PREFIX") { |v| output_prefix = v }
  opt.on("--title=TEXT") { |v| title_override = v }
  opt.on("--width=PX", Integer) { |v| width = v }
  opt.on("--height=PX", Integer) { |v| height = v }
  opt.on("--[no-]render") { |v| render = v }
  opt.on("--[no-]open") { |v| auto_open = v }
end.parse!(global_argv)

flows = parse_flows(flow_argv.dup)
raise ArgumentError, "no flows given; expected: -- label <opts...> -- ..." if flows.empty?
if show_queue && flows.length > 1
  raise ArgumentError, "--queue cannot be used when multiple flows are given"
end

network = NETWORKS.fetch(network_name)
cmd = [
  SIMULATOR,
  "-d", network.fetch(:rtt).to_s,
  "-q", network.fetch(:queue).to_s,
  "-b", (network.fetch(:bw) / 8.0).to_s,
  "-l", length.to_s,
  "-c", cc
]
flows.each do |_label, flow_opts|
  cmd << "--"
  cmd.concat(flow_opts)
end

labels = flows.map(&:first)
values = nil
Open3.popen3(*cmd) do |_stdin, stdout, stderr, wait_thr|
  values = build_values(parse_simulator_output(stdout.each_line), labels, show_queue)
  err = stderr.read
  status = wait_thr.value
  raise "simulator failed: #{err.strip}" unless status.success?
end

missing = labels.reject { |label| values.any? { |value| value["flow"] == label && value["metric"] == "deliver" } }
raise "simulator did not emit data for flows: #{missing.join(", ")}" unless missing.empty?
raise "no data produced by simulator" if values.empty?

spec = build_spec(
  values: values,
  length: length,
  title: (title_override || network_name),
  show_queue: show_queue,
  width: width,
  height: height,
  flow_count: flows.length
)
spec_json = JSON.pretty_generate(spec)

if render
  output_name = "simulator-plot-#{Time.now.strftime("%Y%m%d%H%M%S")}.svg"
  svg_path = output_prefix == "simulator" ? output_name : "#{output_prefix}.svg"
  render_svg(spec_json, svg_path)
  puts "wrote #{svg_path}"
  if auto_open
    system("open", svg_path) || warn("failed to open #{svg_path}")
  end
else
  spec_path = "#{output_prefix}.vl.json"
  File.write(spec_path, spec_json)
  puts "wrote #{spec_path}"
end
