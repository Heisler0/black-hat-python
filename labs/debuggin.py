def sum(n1, n2):
    n1i = convert_integer(n1)
    n2i = convert_integer(n2)
    result = n1i + n2i
    return result

def convert_integer(n):
    return int(n)

answer = sum('1', '2')