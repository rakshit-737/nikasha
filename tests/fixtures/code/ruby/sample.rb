# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
require 'json'

module Billing
  class Invoice
    attr_reader :total

    def initialize(lines)
      @total = sum(lines)
    end

    def self.parse(text)
      new(JSON.parse(text))
    end

    def to_s
      format('%.2f', total)
    end

    private

    def sum(lines)
      lines.map { |l| l.fetch(:amount) }.sum
    end
  end

  def self.version
    '1.0'
  end
end

def helper(x)
  puts Billing::Invoice.parse(x)
end
