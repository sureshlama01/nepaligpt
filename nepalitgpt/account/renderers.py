from rest_framework.renderers import JSONRenderer
import json

class UserRenderer(JSONRenderer):
    charset = 'utf-8'
    def render(self,data,accept_media_type=None,renderer_context=None):
        reponse = ''
        if 'ErrorDetail' in str(data):
            reponse = json.dumps({"errors": data})
        else:
            reponse = json.dumps(data)
        return reponse