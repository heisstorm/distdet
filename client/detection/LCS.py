def lcs_merge_cycle(strings):
    to_remove = set()
    for i in range(len(strings)):
        if i >= len(strings):
            break
        target = strings[i]
        name_i = target.split(',')[1].strip()
        attr_i = target.split(',')[2].strip()
        for j in range(len(strings)):
            if i != j and j not in to_remove:
                freq_target = target.split(',')[0]
                freq_j = strings[j].split(',')[0]
                name_j = strings[j].split(',')[1].strip()
                attr_j = strings[j].split(',')[2].strip()
                # if name_i == name_j:
                lcs_length = lcs(attr_i, attr_j)
                if lcs_length > len(attr_j) / 2:
                    to_remove.add(j)
                    target = "%s, %s, %s" % (int(freq_target) + int(freq_j), name_i, attr_i)
        for k in reversed(sorted(to_remove)):
            strings.remove(strings[k])
        to_remove.clear()
        strings[i] = target

    # Return the list without the elements marked for removal
    return strings


def lcs(X, Y):
    """Compute the Longest Common Substring of X and Y."""
    m, n = len(X), len(Y)
    result = 0  # Length of the longest common substring

    # Create a 2D table to store lengths of longest common suffixes
    # LCStuff[i][j] will hold the length of the longest common suffix of
    # X[0..i-1] and Y[0..j-1]. Using 1-based indexing for convenience.
    LCStuff = [[0] * (n + 1) for _ in range(m + 1)]

    for i in range(m + 1):
        for j in range(n + 1):
            if i == 0 or j == 0:
                LCStuff[i][j] = 0
            elif X[i - 1] == Y[j - 1]:
                LCStuff[i][j] = LCStuff[i - 1][j - 1] + 1
                result = max(result, LCStuff[i][j])
            else:
                LCStuff[i][j] = 0

    return result


if __name__ == '__main__':
    lines = []
    with open('poi.txt', 'r') as f:
        for l in f.readlines():
            lines.append(l.strip().lstrip('(').rstrip(')'))
    reduced_list = lcs_merge_cycle(lines)
    with open('poi_LCS.txt', 'w') as file:
        for value in reduced_list:
            file.write(value + '\n')
