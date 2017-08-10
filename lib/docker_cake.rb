require_relative 'docker_cake/registry_api_client'
require 'time'
require 'terminal-table'

class DockerCake

  attr_accessor :registry

  def initialize(url: nil, user: nil, password: nil)
    @registry ||= RegistryApiClient.new(user: user, password: password, url: url)
  end

  def repo_info(name, tag = 'latest')
    manifest = registry.manifest_layers(name, tag)
    puts print_manifest(manifest)
  end

  def compare_versions(repo_name, filter: /.+/, max: 10)
    tags = registry.tags(repo_name, false)['tags']

    if ENV['DEBUG']
      puts "Found tags: #{tags.join(", ")}"
    end

    tags.select! {|t| t =~ filter}

    selected_tags = tags.last(max)

    if ENV['DEBUG']
      puts "Analyzing #{selected_tags.size} tags: #{selected_tags.join(", ")}..."
    end

    manifests = {}
    procs = selected_tags.map do |tag|
      lambda { manifests[tag] = registry.manifest_layers(repo_name, tag) }
    end
    registry.in_parallel(procs)
    #selected_tags.each do |tag|
    #  manifests[tag] = registry.manifest_layers(repo_name, tag)
    #  #pp manifests[tag]
    #end

    manifests = manifests.sort_by do |tag, list|
      list.map {|l| l['created'] }.max
    end.to_h

    images_map = {}
    counted_layers = []
    result = []

    manifests.each do |tag, layers|
      stats = {name: tag, size: 0, add_img: 0, reuse_img: 0, add_size: 0, layers: 0, date: Time.at(0).to_s}

      map_key = manifests[tag].map {|l| l['blobSum']}.join(',')
      if images_map[map_key]
        stats[:same_as] = images_map[map_key]
      end
      images_map[map_key] ||= tag

      manifests[tag].each do |layer|
        stats[:size] += layer['size'] || 0
        stats[:layers] += 1
        stats[:date] = layer['created'] if layer['created'] > stats[:date]

        layer_key = layer['blobSum'] + "_" + layer['id']

        if counted_layers.include?(layer_key)
          stats[:reuse_img] += 1
        else
          stats[:add_img] += 1
          stats[:add_size] += layer['size'] || 0
        end

        counted_layers << layer_key
      end

      #puts "#{tag} -> #{stats}"
      result << stats
    end

    puts print_comparison(result)
  end

  def print_comparison(result)
    rows = result.map do |stats|
      [
        stats[:name],
        DateTime.parse(stats[:date]).strftime("%F %T"),
        size_to_human(stats[:size]),
        stats[:layers],
        stats[:reuse_img],
        stats[:add_img],
        size_to_human(stats[:add_size]),
        stats[:same_as]
      ]
    end

    table = Terminal::Table.new(headings: ['Tag', 'Date', 'Size', 'Layers', 'Reuse Layers', 'Extra Layers', 'Extra Size', 'Same as'], rows: rows)
  end

  def print_manifest(manifest)
    rows = manifest.map do |layer|
      cmd = layer['container_config'] && layer['container_config']['Cmd'] || ['']
      cmd = cmd.join(" ").gsub('\n', "\n").sub(/#{'/bin/sh -c'}\s+/, '')
      if cmd.start_with?('#(nop)')
        cmd.sub!(/#\(nop\)\s+/, '')
      else
        cmd = "RUN #{cmd}"
      end

      cmd.gsub!("\t", "    ")

      shorter = []
      cmd.lines.each do |line|
        shorter.push(*line.scan(/.{1,90}/))
      end

      [
        layer['id'][0...8],
        DateTime.parse(layer['created']).strftime("%F %T"),
        shorter.join("\n"),
        size_to_human(layer['size'])
      ]
    end

    rows << :separator << [nil, nil, 'TOTAL', size_to_human(manifest.sum {|layer| layer['size'].to_i })]

    table = Terminal::Table.new(headings: ['ID', 'Date', 'CMD', 'Size'], rows: rows)
  end

  def size_to_human(size)
    return '0' unless size

    if size > 1_000_000_000
      "#{(size / 1_000_000_000.0).round(3)} GB"
    elsif size > 1_000_000
      "#{(size / 1_000_000.0).round(3)} MB"
    elsif size > 1_000
      "#{(size / 1_000.0).round(3)} KB"
    else
      "#{size} Bytes"
    end
  end

end
