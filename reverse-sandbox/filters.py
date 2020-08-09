import json

def read_filters():
    temp = {}
    filters = {}
    with open('filters.json') as data:
        temp = json.load(data)

        for key, value in temp.items():
            filters[int(str(key), 16)] = value

    return filters


class Filters(object):

    filters = read_filters()

    @staticmethod
    def exists(id):
        return id in Filters.filters

    @staticmethod
    def get(id):
        return Filters.filters.get(id, None)
