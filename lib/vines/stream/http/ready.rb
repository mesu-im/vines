# encoding: UTF-8

module Vines
  class Stream
    class Http
      class Ready < Client::Ready
        RID, SID, TYPE, TERMINATE = %w[rid sid type terminate].map(&:freeze)

        def node(node)
          unless stream.valid_session?(node[SID]) && body?(node) && node[RID]
            raise StreamErrors::NotAuthorized
          end
          stream.parse_body(node).each do |child|
            begin
              super(child)
            rescue StanzaError => e
              stream.error(e)
            end
          end
          stream.terminate if terminate?(node)
        end

        def terminate?(node)
          node[TYPE] == TERMINATE
        end
      end
    end
  end
end
