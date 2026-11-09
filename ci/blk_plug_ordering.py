"""Recognize reviewed plug teardown shapes, never infer a fix from patch failure.

This is deliberately a small source recognizer, not a general C verifier.
Changes to control flow, flag clearing, macros or conditional compilation need
review. Whitespace, comments and unrelated functions may change freely.
"""
import re

CHECK = 'blk-plug-timestamp-ordering-v1'
SOURCE = 'block/blk-core.c'
NEEDS_BARRIER = 'needs_barrier'

_TOKEN = re.compile(
    r'\s+|/\*[\s\S]*?\*/|//[^\n]*|'
    r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|'
    r'\#[^\n]*|[A-Za-z_]\w*|->|==|!=|&=|\|\||&&|\S')


def tokens(source):
    # C splices escaped newlines before recognizing comments or directives.
    source = re.sub(r'\\\r?\n', '', source)
    return tuple(part for part in _TOKEN.findall(source)
                 if not part.isspace() and not part.startswith(('/*', '//')))


_FLUSH = """
{
    if (!list_empty(&plug->cb_list))
        flush_plug_callbacks(plug, from_schedule);
    blk_mq_flush_plug_list(plug, from_schedule);
    if (unlikely(!rq_list_empty(&plug->cached_rqs)))
        blk_mq_free_plug_rqs(plug);
    plug->cur_ktime = 0;
    current->flags &= ~PF_BLOCK_TS;
}
"""
_FINISH = """
{
    if (plug == current->plug) {
        __blk_flush_plug(plug, false);
        current->plug = NULL;
    }
}
"""
_FLUSH_BARRIER = _FLUSH.replace(
    'current->flags &= ~PF_BLOCK_TS;',
    'current->flags &= ~PF_BLOCK_TS; barrier();')
_FINISH_BARRIER = _FINISH.replace(
    '__blk_flush_plug(plug, false);',
    '__blk_flush_plug(plug, false); barrier();')


def function_body(source_tokens, signature):
    header = tokens(signature + ' {')
    bodies, conditional = [], 0
    protected = {'barrier', 'current', 'PF_BLOCK_TS',
                 'blk_finish_plug', '__blk_flush_plug'}
    for index, token in enumerate(source_tokens):
        if token.startswith('#'):
            directive = re.match(r'#\s*(\w+)(?:\s+(\w+))?', token)
            if not directive:
                continue
            command, argument = directive.groups()
            if command in ('if', 'ifdef', 'ifndef'):
                conditional += 1
            elif command == 'endif':
                conditional -= 1
            elif command in ('define', 'undef') and argument in protected:
                raise ValueError('Plug ordering macro changed; manual review required')
            if conditional < 0 or (command in ('else', 'elif') and not conditional):
                raise ValueError('Unbalanced C conditional; manual review required')
        if source_tokens[index:index + len(header)] != header:
            continue
        if conditional:
            raise ValueError('Conditional plug function; manual review required')
        start = index + len(header) - 1
        depth = 0
        for end in range(start, len(source_tokens)):
            depth += source_tokens[end] == '{'
            depth -= source_tokens[end] == '}'
            if depth == 0:
                bodies.append(source_tokens[start:end + 1])
                break
        else:
            raise ValueError('Unclosed plug function; manual review required')
    if conditional or len(bodies) != 1:
        raise ValueError('Missing or ambiguous plug function; manual review required')
    return bodies[0]


def classify(data):
    if data is None:
        raise ValueError('Plug source is missing; manual review required')
    source_tokens = tokens(data.decode())
    flush = function_body(
        source_tokens, 'void __blk_flush_plug(struct blk_plug *plug, bool from_schedule)')
    finish = function_body(
        source_tokens, 'void blk_finish_plug(struct blk_plug *plug)')
    if flush not in (tokens(_FLUSH), tokens(_FLUSH_BARRIER)):
        raise ValueError('Plug flush or PF_BLOCK_TS clearing changed; manual review required')
    if finish not in (tokens(_FINISH), tokens(_FINISH_BARRIER)):
        raise ValueError('Plug teardown changed; manual review required')
    if finish == tokens(_FINISH_BARRIER):
        return 'barrier_in_finish'
    if flush == tokens(_FLUSH_BARRIER):
        return 'barrier_in_flush'
    return NEEDS_BARRIER


def validate_patch(diff):
    """Only retire the single barrier addition, never other changes to this file."""
    hunks = list(re.finditer(rb'^@@ [^\n]*\n', diff, re.M))
    if len(hunks) != 1:
        raise ValueError('Plug ordering replay patch changed; manual review required')
    old, new = [], []
    for line in diff[hunks[0].end():].splitlines(keepends=True):
        if line[:1] in (b' ', b'-'):
            old.append(line[1:])
        if line[:1] in (b' ', b'+'):
            new.append(line[1:])
        if line[:1] not in (b' ', b'-', b'+'):
            raise ValueError('Unexpected plug ordering hunk; manual review required')
    if (tokens(b''.join(old).decode()) != tokens(_FINISH) or
            tokens(b''.join(new).decode()) != tokens(_FINISH_BARRIER)):
        raise ValueError('Plug ordering replay patch changed; manual review required')
