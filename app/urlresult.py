import numpy as np
import pandas as pd
from app.urlfeatures import URLFeatures
from app.constants import feature_names
from datetime import datetime


def serialize_datetime(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError("Type not serializable")


class URLresult:
    def __init__(self, url, model):

        self.model = model
        self.url = url  # 1
        url_obj = URLFeatures(url)
        ''' 
        self.features_arr = np.array(obj.getFeaturesList()).reshape(1, 29)
        self.features_df = pd.DataFrame(
            self.features_arr, columns=feature_names)  # 2
        '''
        # url extra information dict
        self.extra_info = url_obj.get_extra_info()
        # model features dict
        self.model_features = url_obj.get_model_features()
        self.model_features_arr = np.array(
            list(self.model_features.values())[:29]).reshape(1, 29)
        self.features_df = pd.DataFrame(
            self.model_features_arr, columns=feature_names)

    def get_final_url(self):
        return URLFeatures(self.url).url

    def get_phish_prob(self):
        # Probability to be phishing url
        return self.model.predict_proba(self.features_df)[0, 1]

    def get_isPhish(self):
        # 0 means safe, 1 means phish
        return self.model.predict(self.features_df)[0]

    def get_model_features(self):
        return self.model_features

    def get_extra_info(self):
        return self.extra_info
