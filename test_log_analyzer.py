import unittest
from unittest.mock import patch
from log_analyzer import LogFile, find_newest_log_file, analyze_log


class TestFindNewestLogFile(unittest.TestCase):
    @patch('log_analyzer.os.listdir')
    def test_it_returns_none_if_no_files_in_dir(self, mock_listdir):
        mock_listdir.return_value = []
        files = find_newest_log_file("some_dir")
        self.assertIsNone(files)

    @patch('log_analyzer.os.listdir')
    def test_it_returns_corect_LogFile(self, mock_listdir):
        mock_listdir.return_value = ["nginx-access-ui.log-20170630"]
        log_file = find_newest_log_file("some_dir")
        correct_log_file = LogFile(path_to_file="some_dir",
                                   file_name="nginx-access-ui.log-20170630",
                                   date_in_file_name="2017.06.30",
                                   extension=None)
        self.assertEquals(correct_log_file, log_file)


class TestAnalyzeLog(unittest.TestCase):
    def test_it_returns_correct_snippet(self):
        parser = [("some_url_1", 0.12), ("some_url_2", 0.13), ("some_url_1", 0.13)]
        correct_totals = {"total_requests": 3, "total_time": 0.38}
        correct_urls = {
                 "some_url_1": {"count": 2, "request_times": [0.12, 0.13]},
                 "some_url_2": {"count": 1, "request_times": [0.13]}
                  }
        snippets = analyze_log(parser)
        self.assertTupleEqual((correct_totals, correct_urls), snippets)


if __name__ == '__main__':
    unittest.main(verbosity=2)
