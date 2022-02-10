import { createMachine } from '@xstate/fsm'

function signTags(context: any): boolean {
  return context.signTags()
}

function signContent(context: any): boolean {
  return context.signContent()
}

function dontSignTags(context: any): boolean {
  return !context.signTags()
}

function dontSignTagsOrContent(context: any): boolean {
  return !context.signTags() || !context.signContent()
}

function signTagsAndDontSignContent(context: any): boolean {
  return context.signTags() && !context.signContent()
}

const config = {
  id: 'jose-stream',
  initial: 'initial',
  context: {
    signTags: () => false,
    signContent: () => false
  },
  states: {
    initial: {
      on: {
        HEADER: {
          target: 'header'
        }
      }
    },
    header: {
      on: {
        HEADER_TAG_SIGNATURE: {
          cond: signTags,
          target: 'header_tag_signature'
        },
        BODY: {
          cond: dontSignTags,
          target: 'body'
        }
      }
    },
    header_tag_signature: {
      on: {
        BODY: {
          target: 'body'
        }
      }
    },
    body: {
      on: {
        BODY: {
          target: 'body'
        },
        BODY_END: {
          target: 'body_end'
        }
      }
    },
    body_end: {
      on: {
        CONTENT_SIGNATURE: {
          cond: signContent,
          target: 'content_signature'
        },
        TAG_SIGNATURE: {
          cond: signTagsAndDontSignContent,
          target: 'tag_signature'
        },
        END: {
          cond: dontSignTagsOrContent,
          target: 'complete'
        }
      }
    },
    content_signature: {
      on: {
        TAG_SIGNATURE: {
          cond: signTags,
          target: 'tag_signature'
        },
        END: {
          cond: dontSignTags,
          target: 'complete'
        }
      }
    },
    tag_signature: {
      on: {
        END: {
          target: 'complete'
        }
      }
    },
    complete: {}
  }
}

export function createReaderMachine(context: any) {
  const _config = Object.assign({}, config, { context })

  return createMachine(_config)
}
