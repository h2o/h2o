import sys

def extract_results(results):
    index = 0
    while index < len(results):
        if results[index].startswith('## '):
            end = results.index('\n', index)
            yield results[index:end]
        index += 1

def merge(readme, res):
    title, table = res[0], res[1:]
    assert title in readme, 'Section ' + title + ' missing from README.md'
    secindex = readme.index(title)
    hdrindex = [i for i in range(secindex, len(readme)) if readme[i].startswith('---------- | ')][0]
    start = hdrindex - 1
    end = readme.index('\n', start)
    table = [t.rstrip() + '\n' for t in table]
    return readme[:start] + table + readme[end:]

results = sys.stdin.readlines()
readme = open('../../README.md').readlines()

for res in extract_results(results):
    readme = merge(readme, res)
print ''.join(readme).rstrip()
